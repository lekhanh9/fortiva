// src/auth/gsa.rs
use anyhow::{anyhow, Result};
use plist::{Dictionary, Value};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::time::Duration;

use crate::auth::anisette::AnisetteClient;
use crate::constants::{DEFAULT_CLIENT_INFO, GSA_URL, USER_AGENT as UA};

pub struct GsaClient {
    pub client: Client,
    pub anisette: AnisetteClient,
    pub user_id: String,
    pub device_id: String,
    pub client_info: String,
}

impl GsaClient {
    pub fn new(anisette: AnisetteClient, user_id: String, device_id: String) -> Self {
        // ============================================================
        //  FIX 429: tắt connection pool → mỗi request mở connection mới
        //  (giống requests.Session() + close() bên Python)
        // ============================================================
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .no_proxy()
            .http1_only()   // <-- DÒNG QUAN TRỌNG NHẤT
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            anisette,
            user_id,
            device_id,
            client_info: DEFAULT_CLIENT_INFO.to_string(),
        }
    }

    pub fn request(
        &mut self,
        parameters: HashMap<String, Value>,
        max_retries: u32,
    ) -> Result<Dictionary> {
        self.request_with_headers(parameters, max_retries, None)
    }

    pub fn request_with_headers(
        &mut self,
        parameters: HashMap<String, Value>,
        max_retries: u32,
        extra_headers: Option<HeaderMap>,
    ) -> Result<Dictionary> {
        let op = parameters
            .get("o")
            .and_then(|v| v.as_string())
            .unwrap_or("?")
            .to_string();

        let effective_retries = if op == "apptokens" { 1 } else { max_retries };

        for attempt in 0..effective_retries {
            let cpd = match self.anisette.build_cpd(
                &self.user_id,
                &mut self.device_id,
                &mut self.client_info,
                false, // Giữ nguyên OTP Anisette của session, không làm mới giữa chừng
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[gsa] Khong lay duoc cpd: {}", e);
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };

            let mut request_dict = Dictionary::new();
            request_dict.insert("cpd".into(), json_to_plist(&cpd));

            for (k, v) in &parameters {
                request_dict.insert(k.clone(), v.clone());
            }

            let mut header_dict = Dictionary::new();
            header_dict.insert("Version".into(), Value::String("1.0.1".into()));

            let mut body_dict = Dictionary::new();
            body_dict.insert("Header".into(), Value::Dictionary(header_dict));
            body_dict.insert("Request".into(), Value::Dictionary(request_dict));

            let mut body_bytes: Vec<u8> = Vec::new();
            if let Err(e) = plist::to_writer_xml(&mut body_bytes, &Value::Dictionary(body_dict)) {
                return Err(anyhow!("Plist encode XML that bai: {}", e));
            }

            eprintln!("[gsa] {} (lan {}/{})", op, attempt + 1, effective_retries);

            let mut headers = self.build_headers()?;
            if let Some(extra) = &extra_headers {
                for (k, v) in extra.iter() {
                    headers.insert(k.clone(), v.clone());
                }
            }

            let resp = self
                .client
                .post(GSA_URL)
                .headers(headers)
                .body(body_bytes)
                .send();

            match resp {
                Ok(r) => {
                    let status = r.status();
                    eprintln!("[gsa] HTTP {}", status);

                    if status.as_u16() == 429 {
                        eprintln!("[gsa] 429 rate limit");
                        if attempt + 1 < effective_retries {
                            std::thread::sleep(Duration::from_secs(10));
                            continue;
                        }
                        return Err(anyhow!("GSA 429 rate limit"));
                    }

                    if status.is_server_error() {
                        let wait = std::cmp::min(2u64.pow(attempt) + 1, 15);
                        eprintln!("[gsa] HTTP {} - doi {}s", status, wait);
                        std::thread::sleep(Duration::from_secs(wait));
                        continue;
                    }

                    let bytes = r.bytes()?;

                    // DEBUG: chỉ in khi build dev, bỏ khi release
                    #[cfg(debug_assertions)]
                    {
                        eprintln!("[gsa] === RAW RESPONSE ({} bytes) ===", bytes.len());
                        eprintln!(
                            "{}",
                            String::from_utf8_lossy(&bytes[..bytes.len().min(800)])
                        );
                        eprintln!("[gsa] ================================");
                    }

                    let content = ensure_plist_wrapper(&bytes);

                    let plist_val: Value = match plist::from_bytes(&content) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(anyhow!(
                                "Plist parse that bai: {}. Content: {:?}",
                                e,
                                String::from_utf8_lossy(&content[..content.len().min(200)])
                            ));
                        }
                    };

                    let response = plist_val
                        .as_dictionary()
                        .and_then(|d| d.get("Response"))
                        .and_then(|v| v.as_dictionary())
                        .ok_or_else(|| anyhow!("Response thieu key 'Response'"))?
                        .clone();

                    let ec = response
                        .get("Status")
                        .and_then(|v| v.as_dictionary())
                        .and_then(|d| d.get("ec"))
                        .and_then(plist_integer)
                        .unwrap_or(0);

                    if ec != 0 {
                        let em = response
                            .get("Status")
                            .and_then(|v| v.as_dictionary())
                            .and_then(|d| d.get("em"))
                            .and_then(|v| v.as_string())
                            .unwrap_or("?");
                        eprintln!("[gsa] ec={} em={}", ec, em);
                    } else {
                        eprintln!("[gsa] OK");
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if attempt + 1 >= effective_retries {
                        return Err(anyhow!("GSA HTTP error: {}", e));
                    }
                    eprintln!("[gsa] Loi: {} - thu lai", e);
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }

        Err(anyhow!("GSA request that bai sau {} lan", effective_retries))
    }

    fn build_headers(&mut self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));
        headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(&self.client_info)?,
        );
        headers.insert(
            "X-MMe-Client-Info",
            HeaderValue::from_str(&self.client_info)?,
        );
        headers.insert(
            reqwest::header::CONNECTION,
            HeaderValue::from_static("close"),
        );

        Ok(headers)
    }
}

pub fn ensure_plist_wrapper(bytes: &[u8]) -> Vec<u8> {
    let stripped = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &bytes[i..])
        .unwrap_or(bytes);

    if stripped.starts_with(b"<?xml") || stripped.starts_with(b"bplist") {
        return bytes.to_vec();
    }

    let header = b"<?xml version='1.0' encoding='UTF-8'?>\n<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n<plist version='1.0'>\n";
    let footer = b"\n</plist>";

    let mut out = Vec::with_capacity(header.len() + bytes.len() + footer.len());
    out.extend_from_slice(header);
    out.extend_from_slice(bytes);
    out.extend_from_slice(footer);
    out
}

pub fn json_to_plist(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::String("".into()),
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                Value::Integer((u as i64).into())
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_plist).collect()),
        serde_json::Value::Object(obj) => {
            let mut d = Dictionary::new();
            for (k, val) in obj {
                d.insert(k.clone(), json_to_plist(val));
            }
            Value::Dictionary(d)
        }
    }
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
