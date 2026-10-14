// src/dev/json_api.rs
use anyhow::{anyhow, Result};
use serde_json::Value;

use super::client::{DeveloperClient, BASE_URL_V1};
use crate::auth::AnisetteClient;

impl DeveloperClient {
    /// Liệt kê tất cả certificate IOS_DEVELOPMENT của team hiện tại.
    /// Tự động fallback sang Plist API listAllDevelopmentCerts nếu JSON API không khả dụng.
    pub fn list_certificates(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<Value>> {
        let team_id = self
            .team_id
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa có team_id"))?;

        let url = format!("{}/certificates", BASE_URL_V1);
        let query = format!(
            "teamId={}&filter[certificateType]=IOS_DEVELOPMENT",
            team_id
        );

        if let Ok(resp) = self.request_json(auth, "GET", &url, &query) {
            if let Some(arr) = resp.get("data").and_then(|v| v.as_array()) {
                if !arr.is_empty() {
                    return Ok(arr.clone());
                }
            }
        }

        // Fallback: Plist API listAllDevelopmentCerts (chuẩn cho Free Developer accounts)
        let plist_certs = self.list_all_development_certs(auth)?;
        let json_certs = plist_certs
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.certificate_id,
                    "attributes": {
                        "name": c.name.unwrap_or_default(),
                        "serialNumber": c.serial_number.unwrap_or_default(),
                        "expirationDate": c.expiration_date.unwrap_or_default(),
                        "certificateContent": c.cert_content_b64.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    }
                })
            })
            .collect();

        Ok(json_certs)
    }

    /// Thu hồi certificate theo ID.
    /// Tự động fallback sang Plist API revokeDevelopmentCert nếu JSON API không khả dụng.
    pub fn revoke_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        certificate_id: &str,
    ) -> Result<bool> {
        let team_id = self
            .team_id
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa có team_id"))?;

        let url = format!("{}/certificates/{}", BASE_URL_V1, certificate_id);
        let query = format!("teamId={}", team_id);

        if let Ok(_) = self.request_json(auth, "DELETE", &url, &query) {
            return Ok(true);
        }

        // Fallback: Tìm serialNumber qua list_all_development_certs và gọi Plist revokeDevelopmentCert
        if let Ok(certs) = self.list_all_development_certs(auth) {
            for c in certs {
                if c.certificate_id == certificate_id {
                    if let Some(ref serial) = c.serial_number {
                        return self.revoke_development_cert(auth, serial);
                    }
                }
            }
        }

        eprintln!("[DevAPI] Thu hồi certificate {} thất bại cả JSON và Plist API", certificate_id);
        Ok(false)
    }

    /// Tìm cert content (base64 DER) theo certificate ID.
    /// Retry nhiều lần vì Apple có delay sau khi tạo cert.
    pub fn fetch_certificate_content(
        &mut self,
        auth: &mut AnisetteClient,
        certificate_id: &str,
    ) -> Result<Option<String>> {
        let delays = [1u64, 2, 4, 6];

        for attempt in 0..delays.len() {
            let certs = self.list_certificates(auth)?;

            for cert in certs {
                if cert.get("id").and_then(|v| v.as_str()) == Some(certificate_id) {
                    if let Some(content) = cert
                        .get("attributes")
                        .and_then(|a| a.get("certificateContent"))
                        .and_then(|c| c.as_str())
                    {
                        if !content.is_empty() {
                            return Ok(Some(content.to_string()));
                        }
                    }
                }
            }

            if attempt + 1 < delays.len() {
                std::thread::sleep(std::time::Duration::from_secs(delays[attempt]));
            }
        }

        Ok(None)
    }
}