// src/dev/certificate.rs
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder};
use plist::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::client::{DeveloperClient, plist_integer};
use crate::auth::AnisetteClient;

pub struct CertificateBundle {
    pub certificate_id: Option<String>,
    pub cert_content_b64: Option<String>,
    pub private_key_pem: String,
    pub csr_pem: String,
    pub machine_id: String,
    /// Apple ID đã tạo cert này (để check mismatch khi login account mới)
    pub apple_id: String,
    /// Team ID của cert (verify khi sign)
    pub team_id: String,
}

#[derive(Debug, Clone)]
pub struct DevelopmentCert {
    pub certificate_id: String,
    pub serial_number: Option<String>,
    pub name: Option<String>,
    pub machine_id: Option<String>,
    pub machine_name: Option<String>,
    pub cert_content_b64: Option<String>,
    pub status: Option<String>,
    pub expiration_date: Option<String>,
}

impl DeveloperClient {
    /// Lấy danh sách chứng chỉ iOS Development qua chuẩn Plist API (ios/listAllDevelopmentCerts.action).
    /// Đây là endpoint chính thức được Xcode & isideload sử dụng cho cả tài khoản Free và Trả phí.
    pub fn list_all_development_certs(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<DevelopmentCert>> {
        let resp = self.request_plist(
            auth,
            "ios/listAllDevelopmentCerts.action",
            HashMap::new(),
            true,
        )?;

        let certs_val = match resp.get("certificates").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                let code = resp.get("resultCode").and_then(plist_integer);
                let user_str = resp.get("userString").and_then(|v| v.as_string()).unwrap_or("");
                if let Some(c) = code {
                    if c != 0 {
                        eprintln!("[DevAPI] listAllDevelopmentCerts resultCode {}: {}", c, user_str);
                    }
                }
                return Ok(Vec::new());
            }
        };

        let mut list = Vec::new();
        for item in certs_val {
            let dict = match item.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            let cert_id = dict
                .get("certificateId")
                .or_else(|| dict.get("certRequestId"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();

            if cert_id.is_empty() {
                continue;
            }

            let serial = dict
                .get("serialNumber")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let name = dict
                .get("name")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let machine_id = dict
                .get("machineId")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let machine_name = dict
                .get("machineName")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let cert_content_b64 = dict
                .get("certContent")
                .and_then(|v| v.as_data())
                .map(|bytes| general_purpose::STANDARD.encode(bytes));

            let status = dict
                .get("status")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let exp = dict
                .get("expirationDate")
                .and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Date(d) => Some(d.to_xml_format()),
                    _ => None,
                });

            list.push(DevelopmentCert {
                certificate_id: cert_id,
                serial_number: serial,
                name,
                machine_id,
                machine_name,
                cert_content_b64,
                status,
                expiration_date: exp,
            });
        }

        Ok(list)
    }

    /// Thu hồi chứng chỉ theo số serial qua Plist API (ios/revokeDevelopmentCert.action).
    pub fn revoke_development_cert(
        &mut self,
        auth: &mut AnisetteClient,
        serial_number: &str,
    ) -> Result<bool> {
        let mut params = HashMap::new();
        params.insert("serialNumber".into(), Value::String(serial_number.to_string()));

        let resp = self.request_plist(
            auth,
            "ios/revokeDevelopmentCert.action",
            params,
            true,
        )?;

        let code = resp.get("resultCode").and_then(plist_integer).unwrap_or(0);
        if code == 0 {
            Ok(true)
        } else {
            let user_str = resp.get("userString").and_then(|v| v.as_string()).unwrap_or("");
            eprintln!("[DevAPI] Thu hồi cert (serial: {}) thất bại: {} (code {})", serial_number, user_str, code);
            Ok(false)
        }
    }

    /// Tạo cert mới: sinh RSA key, tạo CSR, gửi Apple, tự động xử lý thu hồi nếu đạt giới hạn (mã 7460).
    pub fn create_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        machine_name: &str,
        apple_id: &str,
        team_id: &str,
    ) -> Result<Option<CertificateBundle>> {
        self.set_team(team_id.to_string());
        eprintln!("[DevAPI] Bắt đầu quy trình tạo chứng chỉ Apple Development...");

        // 1. Sinh RSA key 2048-bit
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        // 2. Tạo CSR với đầy đủ Subject Distinguished Name theo chuẩn Apple
        let csr_pem = build_csr(&pkey, machine_name)?;

        // 3. Vòng lặp gửi CSR và xử lý mã 7460 (tự động thu hồi cert cũ nếu đạt giới hạn)
        let mut attempts = 0;
        let mut cert_id_opt: Option<String> = None;
        let machine_id = Uuid::new_v4().to_string().to_uppercase();

        while attempts < 3 {
            attempts += 1;

            let mut params = HashMap::new();
            params.insert("csrContent".into(), Value::String(csr_pem.clone()));
            params.insert("machineId".into(), Value::String(machine_id.clone()));
            params.insert("machineName".into(), Value::String(machine_name.to_string()));
            params.insert("teamId".into(), Value::String(team_id.to_string()));

            let resp = self.request_plist(
                auth,
                "ios/submitDevelopmentCSR.action",
                params,
                true,
            )?;

            let result_code = resp.get("resultCode").and_then(plist_integer).unwrap_or(0);
            let user_str = resp.get("userString")
                .or_else(|| resp.get("resultString"))
                .and_then(|v| v.as_string())
                .unwrap_or("");

            if result_code == 0 {
                if let Some(cert_req) = resp.get("certRequest").and_then(|v| v.as_dictionary()) {
                    cert_id_opt = cert_req
                        .get("certificateId")
                        .or_else(|| cert_req.get("certRequestId"))
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_string());
                    break;
                } else {
                    eprintln!("[DevAPI] ⚠️ submitDevelopmentCSR trả về resultCode 0 nhưng không có certRequest");
                }
            } else if result_code == 7460 {
                eprintln!("[DevAPI] ⚠️ Apple phản hồi mã 7460 (Đạt giới hạn chứng chỉ / Đã có chứng chỉ đang hoạt động): {}", user_str);
                eprintln!("[DevAPI] Đang lấy danh sách chứng chỉ trên Apple Developer để tự động giải phóng...");

                let remote_certs = self.list_all_development_certs(auth).unwrap_or_default();
                if remote_certs.is_empty() {
                    eprintln!("[DevAPI] ❌ Không tìm thấy chứng chỉ nào trên Apple để thu hồi.");
                    return Err(anyhow!("Apple giới hạn chứng chỉ (7460): {}", user_str));
                }

                // Thu hồi cert đầu tiên có serial number
                let mut revoked = false;
                for rc in &remote_certs {
                    if let Some(ref serial) = rc.serial_number {
                        eprintln!("[DevAPI] Đang thu hồi chứng chỉ cũ '{}' (ID: {}, Serial: {})...", 
                            rc.name.as_deref().unwrap_or("?"), rc.certificate_id, serial);
                        if self.revoke_development_cert(auth, serial)? {
                            eprintln!("[DevAPI] ✅ Đã thu hồi chứng chỉ cũ thành công!");
                            revoked = true;
                            break;
                        }
                    }
                }

                if !revoked {
                    return Err(anyhow!("Không thể thu hồi chứng chỉ cũ trên Apple (7460): {}", user_str));
                }

                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            } else {
                eprintln!("[DevAPI] ❌ Apple từ chối submitDevelopmentCSR: mã {}: {}", result_code, user_str);
                return Err(anyhow!("Apple từ chối tạo chứng chỉ (mã {}): {}", result_code, user_str));
            }
        }

        let cert_id = match cert_id_opt {
            Some(id) => id,
            None => {
                eprintln!("[DevAPI] Không lấy được certificateId từ Apple response");
                return Ok(None);
            }
        };

        // 4. Export private key PEM
        let private_key_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8()?,
        )?;

        // 5. Lấy cert content từ Apple Plist API
        let mut cert_content_b64 = None;
        for retry in 0..3 {
            let remote_certs = self.list_all_development_certs(auth).unwrap_or_default();
            for rc in &remote_certs {
                if rc.certificate_id == cert_id {
                    if let Some(ref b64) = rc.cert_content_b64 {
                        cert_content_b64 = Some(b64.clone());
                        break;
                    }
                }
            }
            if cert_content_b64.is_some() {
                break;
            }
            if retry < 2 {
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }

        // Fallback: nếu listAllDevelopmentCerts không tìm thấy đúng ID, lấy cert có cert_content mới nhất
        if cert_content_b64.is_none() {
            let remote_certs = self.list_all_development_certs(auth).unwrap_or_default();
            if let Some(first_with_content) = remote_certs.iter().find(|rc| rc.cert_content_b64.is_some()) {
                cert_content_b64 = first_with_content.cert_content_b64.clone();
            }
        }

        Ok(Some(CertificateBundle {
            certificate_id: Some(cert_id),
            cert_content_b64,
            private_key_pem,
            csr_pem,
            machine_id,
            apple_id: apple_id.to_string(),
            team_id: team_id.to_string(),
        }))
    }
}

/// Tạo CSR PEM từ RSA key theo định dạng chuẩn Apple Developer.
fn build_csr(pkey: &PKey<Private>, common_name: &str) -> Result<String> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "STATE")?;
    name_builder.append_entry_by_text("L", "LOCAL")?;
    name_builder.append_entry_by_text("O", "ORGNIZATION")?;
    name_builder.append_entry_by_text("CN", common_name)?;
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(pkey)?;
    req_builder.sign(pkey, MessageDigest::sha256())?;

    let req: X509Req = req_builder.build();
    let pem = req.to_pem()?;

    Ok(String::from_utf8(pem)?)
}

/// Decode cert content từ Apple (base64 DER) thành DER bytes.
pub fn decode_cert_content(b64: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("Base64 decode cert: {}", e))
}

// ============================================================
//  ENSURE_CERTIFICATE
// ============================================================

impl DeveloperClient {
    /// Đảm bảo có cert hợp lệ:
    /// 1. Kiểm tra cert lưu cục bộ:
    ///    - Nếu cert cũ thuộc account/team khác -> tự động dọn sạch.
    ///    - Nếu cert cũ thuộc đúng account/team -> kiểm tra xem có còn active trên Apple Developer không.
    ///    - Nếu cert bị thu hồi / hết hạn trên Apple -> tự động xóa cert vô hiệu hóa.
    ///    - Nếu cert còn hợp lệ -> tái sử dụng luôn.
    /// 2. Nếu cần tạo mới:
    ///    - Tự động gọi create_certificate (đã tích hợp tự động thu hồi cert cũ nếu đạt giới hạn).
    ///    - Lưu vào ~/.fortiva/certs/, trả về bundle.
    pub fn ensure_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        machine_name: &str,
        apple_id: &str,
        team_id: &str,
    ) -> Result<CertificateBundle> {
        self.set_team(team_id.to_string());
        let certs_dir = crate::session::Session::dir()?.join("certs");
        std::fs::create_dir_all(&certs_dir)?;

        // Lấy danh sách certs active trên Apple Developer qua Plist API
        let remote_certs = self.list_all_development_certs(auth).unwrap_or_default();

        // 1. Kiểm tra cert đã lưu cục bộ
        if let Some(cert) = CertificateBundle::load_latest(&certs_dir)? {
            let has_meta = !cert.apple_id.is_empty() && !cert.team_id.is_empty();

            if !has_meta || cert.apple_id != apple_id || cert.team_id != team_id {
                println!("[cert] ⚠️ Cert lưu trên máy thuộc tài khoản khác hoặc thiếu metadata. Tự động dọn sạch cert cũ...");
                let _ = clear_all_certs();
            } else if cert.cert_content_b64.is_none() || cert.is_expired() {
                println!("[cert] ⚠️ Cert lưu trên máy (ID: {:?}) đã hết hạn hoặc không có dữ liệu chứng chỉ. Tự động xoá...", cert.certificate_id);
                let _ = clear_all_certs();
            } else {
                // Kiểm tra cert cục bộ có còn active trên Apple Developer không
                let mut is_active = false;
                if let Some(ref cid) = cert.certificate_id {
                    for rc in &remote_certs {
                        if &rc.certificate_id == cid {
                            if rc.status.as_deref().unwrap_or("Active").eq_ignore_ascii_case("Active") {
                                is_active = true;
                            }
                            break;
                        }
                    }
                }

                if is_active || remote_certs.is_empty() {
                    println!("[cert] ✅ Tái sử dụng cert đã lưu: ID {:?} (hợp lệ trên Apple Developer)", cert.certificate_id.as_deref().unwrap_or("?"));
                    return Ok(cert);
                } else {
                    println!("[cert] ⚠️ Cert lưu trên máy (ID: {:?}) đã bị thu hồi hoặc hết hạn trên Apple. Tự động xoá...", cert.certificate_id);
                    let _ = clear_all_certs();
                }
            }
        }

        // 2. Tạo cert mới
        println!("[cert] 🔑 Đang tạo chứng chỉ mới cho {} / {}...", apple_id, team_id);
        let bundle = self
            .create_certificate(auth, machine_name, apple_id, team_id)?
            .ok_or_else(|| anyhow!("Tạo chứng chỉ thất bại (Apple không trả về certRequest)"))?;

        bundle.save_to_disk(&certs_dir)?;
        println!("[cert] ✅ Đã lưu chứng chỉ mới vào {}", certs_dir.display());
        Ok(bundle)
    }
}

/// Check cert hiện tại có khớp account/team không.
pub fn cert_matches_account(apple_id: &str, team_id: &str) -> bool {
    let certs_dir = match crate::session::Session::dir() {
        Ok(d) => d.join("certs"),
        Err(_) => return false,
    };
    if !certs_dir.exists() { return false; }

    for entry in std::fs::read_dir(&certs_dir).into_iter().flatten() {
        let path = match entry { Ok(e) => e.path(), Err(_) => continue };
        if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                let meta_apple = v.get("apple_id").and_then(|x| x.as_str()).unwrap_or("");
                let meta_team = v.get("team_id").and_then(|x| x.as_str()).unwrap_or("");
                if meta_apple.is_empty() || meta_team.is_empty() { return false; }
                return meta_apple == apple_id && meta_team == team_id;
            }
        }
    }
    false
}

/// Xóa toàn bộ cert + key + meta.
pub fn clear_all_certs() -> Result<()> {
    let certs_dir = crate::session::Session::dir()?.join("certs");
    if certs_dir.exists() {
        std::fs::remove_dir_all(&certs_dir)?;
    }
    std::fs::create_dir_all(&certs_dir)?;
    println!("[cert] ✅ Đã xóa toàn bộ cert cũ");
    Ok(())
}

impl CertificateBundle {
    pub fn save_to_disk(&self, dir: &std::path::Path) -> Result<()> {
        let id = self.certificate_id.as_ref()
            .ok_or_else(|| anyhow!("Bundle thiếu certificate_id"))?;

        if let Some(content) = &self.cert_content_b64 {
            std::fs::write(dir.join(format!("{}.cert", id)), content)?;
        }

        std::fs::write(dir.join(format!("{}.key", id)), &self.private_key_pem)?;

        let meta = serde_json::json!({
            "certificate_id": id,
            "machine_id": self.machine_id,
            "csr_pem": self.csr_pem,
            "saved_at": crate::session::now(),
            "apple_id": self.apple_id,
            "team_id": self.team_id,
        });
        std::fs::write(
            dir.join(format!("{}.meta.json", id)),
            serde_json::to_string_pretty(&meta)?,
        )?;

        eprintln!("[DevAPI] Đã lưu cert {} vào {}", id, dir.display());
        Ok(())
    }

    pub fn load_from_id(dir: &std::path::Path, cert_id: &str) -> Result<Option<Self>> {
        let cert_path = dir.join(format!("{}.cert", cert_id));
        let key_path = dir.join(format!("{}.key", cert_id));
        let meta_path = dir.join(format!("{}.meta.json", cert_id));

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_content_b64 = std::fs::read_to_string(&cert_path).ok();
        let private_key_pem = std::fs::read_to_string(&key_path)?;
        let (machine_id, apple_id, team_id) = if meta_path.exists() {
            let meta_str = std::fs::read_to_string(&meta_path)?;
            let meta: serde_json::Value = serde_json::from_str(&meta_str)?;
            (
                meta.get("machine_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                meta.get("apple_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                meta.get("team_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new(), String::new())
        };

        Ok(Some(CertificateBundle {
            certificate_id: Some(cert_id.to_string()),
            cert_content_b64,
            private_key_pem,
            csr_pem: String::new(),
            machine_id,
            apple_id,
            team_id,
        }))
    }

    pub fn load_latest(dir: &std::path::Path) -> Result<Option<Self>> {
        let mut latest: Option<(u64, String)> = None;

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let (Some(id), Some(saved)) = (
                                meta.get("certificate_id").and_then(|v| v.as_str()),
                                meta.get("saved_at").and_then(|v| v.as_u64()),
                            ) {
                                if latest.as_ref().map(|(t, _)| saved > *t).unwrap_or(true) {
                                    latest = Some((saved, id.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some((_, id)) = latest {
            return Self::load_from_id(dir, &id);
        }
        Ok(None)
    }

    pub fn is_expired(&self) -> bool {
        let content = match &self.cert_content_b64 {
            Some(c) if !c.trim().is_empty() => c.trim(),
            _ => return false,
        };

        let clean_b64: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        let cert = if content.contains("-----BEGIN CERTIFICATE-----") {
            openssl::x509::X509::from_pem(content.as_bytes()).ok()
        } else if let Ok(der) = general_purpose::STANDARD.decode(&clean_b64) {
            openssl::x509::X509::from_der(&der).ok()
        } else {
            None
        };

        match cert {
            Some(cert) => {
                if let Ok(now) = openssl::asn1::Asn1Time::from_unix((crate::session::now() as i64) as _) {
                    cert.not_after() < now.as_ref()
                } else {
                    false
                }
            }
            None => true, // Cert bị lỗi format hoặc hư hỏng coi như hết hạn/vô hiệu
        }
    }
}

/// Parse chuỗi ngày hết hạn từ Apple Developer API sang UTC DateTime.
/// Hỗ trợ RFC3339 chuẩn, ISO 8601 không dấu hai chấm (+0000), naive datetime, và ngày (YYYY-MM-DD).
pub fn parse_expiration_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // 1. Thử RFC3339 chuẩn: 2024-11-20T12:34:56Z hoặc 2024-11-20T12:34:56.000+00:00
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // 2. Thử timezone offset không có dấu hai chấm: 2024-11-20T12:34:56.000+0000
    if let Ok(dt) = chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // 3. Thử Naive DateTime (mặc định coi là UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    // 4. Thử YYYY-MM-DD
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        if let Some(dt) = d.and_hms_opt(23, 59, 59) {
            return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
        }
    }
    None
}