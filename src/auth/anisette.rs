// src/auth/anisette.rs
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::constants::{ANISETTE_FALLBACK, fix_client_info};
use crate::config::Config;

pub struct AnisetteClient {
    url: String,
    cached: Option<HashMap<String, String>>,
    cache_time: Option<Instant>,
}

impl AnisetteClient {
    pub fn new(url: Option<&str>) -> Self {
        let final_url = url
            .map(|s| s.to_string())
            .unwrap_or_else(Config::anisette_url);

        Self {
            url: final_url,
            cached: None,
            cache_time: None,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn fetch(&mut self, force: bool) -> Result<HashMap<String, String>> {
        if !force {
            if let (Some(cached), Some(t)) = (&self.cached, self.cache_time) {
                if t.elapsed() < Duration::from_secs(30) {
                    return Ok(cached.clone());
                }
            }
        }

        let mut servers = vec![self.url.clone()];
        for s in ANISETTE_FALLBACK {
            if *s != self.url {
                servers.push(s.to_string());
            }
        }

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()?;

        for srv in &servers {
            let resp = match client.get(srv).send() {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

            // Dung bytes thay vi json() de tranh InvalidUtf8AsciiStream
            let bytes = match resp.bytes() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[anisette] read bytes fail: {}", e);
                    continue;
                }
            };
            
            let data: HashMap<String, Value> = match serde_json::from_slice(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[anisette] JSON parse fail: {}", e);
                    eprintln!("[anisette] first 200 bytes: {:?}",
                        String::from_utf8_lossy(&bytes[..bytes.len().min(200)]));
                    continue;
                }
            };

            if !data.contains_key("X-Apple-I-MD-M") {
                continue;
            }

            let mut result = HashMap::new();
            for (k, v) in data {
                if let Some(s) = v.as_str() {
                    result.insert(k, s.to_string());
                }
            }
            self.cached = Some(result.clone());
            self.cache_time = Some(Instant::now());

            return Ok(result);
        }

        Err(anyhow!("Không lấy được anisette từ server nào"))
    }

    pub fn get_meta_headers(user_id: &str, device_id: &str) -> HashMap<String, String> {
        let mut h = HashMap::new();
        let now = Utc::now();
        let client_time = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        h.insert("X-Apple-I-Client-Time".into(), client_time);
        h.insert("X-Apple-I-TimeZone".into(), "UTC".into());
        h.insert("loc".into(), "en_US".into());
        h.insert("X-Apple-Locale".into(), "en_US".into());
        h.insert("X-Apple-I-MD-RINFO".into(), "17106176".into());
        h.insert(
            "X-Apple-I-MD-LU".into(),
            general_purpose::STANDARD.encode(user_id.as_bytes()),
        );
        h.insert("X-Mme-Device-Id".into(), device_id.to_string());
        h.insert("X-Apple-I-SRL-NO".into(), "0".into());

        h
    }

    pub fn build_cpd(
        &mut self,
        user_id: &str,
        device_id: &mut String,
        client_info: &mut String,
        force: bool,
    ) -> Result<Value> {
        let anisette = self.fetch(force)?;

        if let Some(did) = anisette.get("X-Mme-Device-Id") {
            *device_id = did.clone();
        }
        if let Some(ci) = anisette.get("X-MMe-Client-Info") {
            *client_info = fix_client_info(ci);
        }

        let meta = Self::get_meta_headers(user_id, device_id);

        let mut cpd = json!({
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "loc": "en_US",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": anisette.get("X-Apple-I-MD").cloned().unwrap_or_default(),
            "X-Apple-I-MD-M": anisette.get("X-Apple-I-MD-M").cloned().unwrap_or_default(),
            "X-Mme-Device-Id": anisette.get("X-Mme-Device-Id").cloned().unwrap_or_else(|| device_id.clone()),
            "X-Apple-I-MD-LU": anisette.get("X-Apple-I-MD-LU").cloned().unwrap_or_default(),
            "X-Apple-I-MD-RINFO": anisette.get("X-Apple-I-MD-RINFO").cloned().unwrap_or_else(|| "17106176".to_string()),
            "X-Apple-I-SRL-NO": anisette.get("X-Apple-I-SRL-NO").cloned().unwrap_or_else(|| "0".to_string()),
            "X-Apple-I-Client-Time": anisette.get("X-Apple-I-Client-Time").cloned().unwrap_or_else(|| meta.get("X-Apple-I-Client-Time").cloned().unwrap_or_default()),
            "X-Apple-I-TimeZone": anisette.get("X-Apple-I-TimeZone").cloned().unwrap_or_else(|| "UTC".to_string()),
            "X-MMe-Client-Info": client_info.clone(),
        });

        if let Some(obj) = cpd.as_object_mut() {
            for (k, v) in meta {
                obj.entry(k).or_insert(Value::String(v));
            }
        }

        Ok(cpd)
    }
}