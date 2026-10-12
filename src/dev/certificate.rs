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

use super::client::DeveloperClient;
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

impl DeveloperClient {
    /// Tạo cert mới hoàn chỉnh: sinh RSA key, tạo CSR, gửi Apple, lấy cert về.
    pub fn create_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        machine_name: &str,
        apple_id: &str,
        team_id: &str,
    ) -> Result<Option<CertificateBundle>> {
        eprintln!("[DevAPI] Tạo certificate mới...");

        // 1. Sinh RSA key 2048-bit
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        // 2. Tạo CSR
        let csr_pem = build_csr(&pkey, machine_name)?;

        // 3. Gửi lên Apple
        let machine_id = Uuid::new_v4().to_string().to_uppercase();

        let mut params = HashMap::new();
        params.insert("csrContent".into(), Value::String(csr_pem.clone()));
        params.insert("machineId".into(), Value::String(machine_id.clone()));
        params.insert(
            "machineName".into(),
            Value::String(machine_name.to_string()),
        );

        let resp = self.request_plist(
            auth,
            "ios/submitDevelopmentCSR.action",
            params,
            true,
        )?;

        let cert_request = match resp.get("certRequest").and_then(|v| v.as_dictionary()) {
            Some(d) => d.clone(),
            None => {
                eprintln!("[DevAPI] Không có certRequest trong response");
                return Ok(None);
            }
        };

        // 4. Export private key PEM
        let private_key_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8()?,
        )?;

        // 5. Fetch cert content (retry)
        let cert_id = cert_request
            .get("certificateId")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        let cert_content_b64 = if let Some(id) = &cert_id {
            self.fetch_certificate_content(auth, id)?
        } else {
            None
        };

        Ok(Some(CertificateBundle {
            certificate_id: cert_id,
            cert_content_b64,
            private_key_pem,
            csr_pem,
            machine_id,
            apple_id: apple_id.to_string(),
            team_id: team_id.to_string(),
        }))
    }
}

/// Tạo CSR PEM từ RSA key.
fn build_csr(pkey: &PKey<Private>, common_name: &str) -> Result<String> {
    let mut name_builder = X509NameBuilder::new()?;
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
    ///    - Kiểm tra số lượng cert hiện có trên Apple. Nếu >= 3 (giới hạn free account) -> tự động revoke cert cũ nhất.
    ///    - Tạo cert mới, lưu vào ~/.fortiva/certs/, trả về bundle.
    pub fn ensure_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        machine_name: &str,
        apple_id: &str,
        team_id: &str,
    ) -> Result<CertificateBundle> {
        let certs_dir = crate::session::Session::dir()?.join("certs");
        std::fs::create_dir_all(&certs_dir)?;

        // Lấy danh sách certs active trên Apple Developer
        let remote_certs_result = self.list_certificates(auth);

        // Kiểm tra cert đã lưu cục bộ
        if let Some(cert) = CertificateBundle::load_latest(&certs_dir)? {
            let has_meta = !cert.apple_id.is_empty() && !cert.team_id.is_empty();

            if !has_meta || cert.apple_id != apple_id || cert.team_id != team_id {
                println!("[cert] ⚠️ Cert lưu trên máy thuộc tài khoản khác hoặc thiếu metadata. Tự động dọn sạch cert cũ...");
                let _ = clear_all_certs();
            } else if cert.cert_content_b64.is_none() || cert.is_expired() {
                println!("[cert] ⚠️ Cert lưu trên máy (ID: {:?}) đã hết hạn hoặc không có dữ liệu chứng chỉ. Tự động xoá...", cert.certificate_id);
                let _ = clear_all_certs();
            } else {
                // Cert cục bộ còn hiệu lực. Kiểm tra trạng thái trên Apple Developer nếu kết nối được.
                match &remote_certs_result {
                    Ok(remote_certs) => {
                        let mut is_active = false;
                        if let Some(cid) = &cert.certificate_id {
                            for rc in remote_certs {
                                if rc.get("id").and_then(|v| v.as_str()) == Some(cid) {
                                    if let Some(exp_str) = rc
                                        .get("attributes")
                                        .and_then(|a| a.get("expirationDate"))
                                        .and_then(|e| e.as_str())
                                    {
                                        if let Some(exp_time) = parse_expiration_date(exp_str) {
                                            if exp_time < chrono::Utc::now() {
                                                println!("[cert] ⚠️ Cert ID {} đã hết hạn trên Apple vào {}", cid, exp_str);
                                                break;
                                            }
                                        }
                                    }
                                    is_active = true;
                                    break;
                                }
                            }
                        }

                        if is_active {
                            println!("[cert] ✅ Tái sử dụng cert đã lưu: ID {:?} (hợp lệ trên Apple Developer)", cert.certificate_id.as_deref().unwrap_or("?"));
                            return Ok(cert);
                        } else {
                            println!("[cert] ⚠️ Cert lưu trên máy (ID: {:?}) đã bị thu hồi hoặc hết hạn trên Apple. Tự động xoá...", cert.certificate_id);
                            let _ = clear_all_certs();
                        }
                    }
                    Err(e) => {
                        println!("[cert] ⚠️ Không thể kết nối Apple Developer API để kiểm tra từ xa ({}). Tiếp tục sử dụng cert hợp lệ đã lưu trên máy.", e);
                        return Ok(cert);
                    }
                }
            }
        }

        let remote_certs = match remote_certs_result {
            Ok(certs) => certs,
            Err(_) => self.list_certificates(auth).unwrap_or_default(),
        };

        // Tự động giải phóng nếu đã đạt giới hạn 3 certs của Free Developer Account
        if remote_certs.len() >= 3 {
            println!(
                "[cert] ⚠️ Đã đạt giới hạn chứng chỉ Apple ({}/3). Tự động thu hồi chứng chỉ cũ nhất...",
                remote_certs.len()
            );
            super::max_certs::handle_max_certs(
                self,
                auth,
                &remote_certs,
                &super::max_certs::MaxCertsBehavior::AutoRevokeOldest,
            )?;
        }

        // Tạo cert mới
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
                if let Ok(now) = openssl::asn1::Asn1Time::from_unix(crate::session::now() as i64) {
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