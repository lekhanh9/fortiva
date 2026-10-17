// src/dev/client.rs
use anyhow::{anyhow, Result};
use plist::{Dictionary, Value};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::auth::error::{SessionExpiredError, is_session_expired_response};
use crate::auth::anisette::AnisetteClient;
use crate::constants::DEFAULT_CLIENT_INFO;

pub const BASE_URL_QH65B2: &str = "https://developerservices2.apple.com/services/QH65B2";
pub const BASE_URL_V1: &str = "https://developerservices2.apple.com/services/v1";
pub const CLIENT_ID: &str = "XABBG36SBA";
pub const PROTOCOL_VERSION: &str = "QH65B2";
pub const XCODE_VERSION: &str = "14.2 (14C18)";

#[derive(Debug, Clone)]
pub struct DevError {
    pub result_code: Option<i64>,
    pub user_string: String,
}

pub struct DeveloperClient {
    pub dsid: String,
    pub session_token: String,
    pub team_id: Option<String>,
    pub last_error: Option<DevError>,
    pub client: Client,
    pub anisette_cache: AnisetteCache,
    pub client_info: Option<String>,
}

pub struct AnisetteCache {
    cached: Option<HashMap<String, String>>,
    cache_time: Option<Instant>,
}

impl AnisetteCache {
    pub fn new() -> Self {
        Self { cached: None, cache_time: None }
    }

    pub fn get(
        &mut self,
        auth: &mut AnisetteClient,
        force: bool,
    ) -> Result<HashMap<String, String>> {
        if !force {
            if let (Some(c), Some(t)) = (&self.cached, self.cache_time) {
                if t.elapsed() < Duration::from_secs(60) {
                    return Ok(c.clone());
                }
            }
        }
        let fresh = auth.fetch(true)?;
        self.cached = Some(fresh.clone());
        self.cache_time = Some(Instant::now());
        Ok(fresh)
    }
}

impl DeveloperClient {
    pub fn new(dsid: String, session_token: String) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        let client_info = Some(crate::config::Config::client_info());

        Ok(Self {
            dsid,
            session_token,
            team_id: None,
            last_error: None,
            client,
            anisette_cache: AnisetteCache::new(),
            client_info,
        })
    }

    pub fn set_client_info(&mut self, client_info: String) {
        self.client_info = Some(client_info);
    }

    pub fn set_team(&mut self, team_id: String) {
        self.team_id = Some(team_id);
    }

    pub fn auth_headers_plist(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
    ) -> Result<HeaderMap> {
        self.build_headers(auth, force_anisette, "text/x-xml-plist", "text/x-xml-plist")
    }

    pub fn auth_headers_json(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
    ) -> Result<HeaderMap> {
        self.build_headers(auth, force_anisette, "application/vnd.api+json", "application/vnd.api+json")
    }

    fn build_headers(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
        content_type: &str,
        accept: &str,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);
        headers.insert(ACCEPT, HeaderValue::from_str(accept)?);
        // Định danh Xcode chuẩn tương thích 100% tài khoản Free Developer & Personal Team
        headers.insert(USER_AGENT, HeaderValue::from_static("Xcode"));
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.insert("X-Apple-App-Info", HeaderValue::from_static("com.apple.gs.xcode.auth"));
        headers.insert("X-Xcode-Version", HeaderValue::from_static(XCODE_VERSION));
        headers.insert("X-Apple-I-Identity-Id", HeaderValue::from_str(&self.dsid)?);
        headers.insert("X-Apple-GS-Token", HeaderValue::from_str(&self.session_token)?);
        headers.insert(
            reqwest::header::CONNECTION,
            HeaderValue::from_static("close"),
        );

        let anisette = self.anisette_cache.get(auth, force_anisette)?;
        let mut has_client_info = false;
        for (k, v) in anisette {
            if k.eq_ignore_ascii_case("x-mme-client-info") {
                has_client_info = true;
                let ci_to_use = self.client_info.as_deref().unwrap_or(&v);
                if let Ok(value) = HeaderValue::from_str(ci_to_use) {
                    headers.insert(reqwest::header::HeaderName::from_static("x-mme-client-info"), value);
                }
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                headers.insert(name, value);
            }
        }

        if !has_client_info {
            let default_ci = self.client_info.as_deref().unwrap_or(DEFAULT_CLIENT_INFO);
            if let Ok(val) = HeaderValue::from_str(default_ci) {
                headers.insert("X-Mme-Client-Info", val);
            }
        }

        Ok(headers)
    }

    pub fn request_plist(
        &mut self,
        auth: &mut AnisetteClient,
        action: &str,
        extra_params: HashMap<String, Value>,
        require_team: bool,
    ) -> Result<Dictionary> {
        for attempt in 0..2 {
            let headers = self.auth_headers_plist(auth, false)?;

            let mut params = Dictionary::new();
            params.insert("clientId".into(), Value::String(CLIENT_ID.into()));
            params.insert("protocolVersion".into(), Value::String(PROTOCOL_VERSION.into()));
            params.insert("requestId".into(), Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()));
            params.insert("userLocale".into(), Value::Array(vec![Value::String("en_US".into())]));

            if require_team {
                let team = self.team_id.as_ref().ok_or_else(|| anyhow!("Chua co team_id"))?;
                params.insert("teamId".into(), Value::String(team.clone()));
            }

            for (k, v) in &extra_params {
                params.insert(k.clone(), v.clone());
            }

            let url = format!("{}/{}?clientId={}", BASE_URL_QH65B2, action, CLIENT_ID);

            let mut body = Vec::new();
            plist::to_writer_xml(&mut body, &Value::Dictionary(params))?;

            let resp = self.client.post(&url).headers(headers).body(body).send();

            match resp {
                Ok(r) => {
                    if r.status().as_u16() >= 500 {
                        eprintln!("[DevAPI] Loi {} - thu lai...", r.status());
                        std::thread::sleep(Duration::from_secs(2));
                        continue;
                    }

                    let status = r.status();
                    let bytes = r.bytes()?;
                    let plist_val: Value = plist::from_bytes(&bytes)?;
                    let dict = plist_val
                        .as_dictionary()
                        .ok_or_else(|| anyhow!("Response khong phai dict"))?
                        .clone();

                    let result_code = dict
                        .get("resultCode")
                        .or_else(|| dict.get("resultcode"))
                        .and_then(plist_integer);

                    let user_string = dict.get("userString")
                        .or_else(|| dict.get("resultString"))
                        .and_then(|v| v.as_string())
                        .unwrap_or("");

                    if let Some(code) = result_code {
                        if code != 0 {
                            self.last_error = Some(DevError {
                                result_code: Some(code),
                                user_string: user_string.to_string(),
                            });
                            if code != 1100 {
                                eprintln!("[DevAPI] {} phản hồi resultCode {}: {}", action, code, user_string);
                            }
                        }
                    }

                    if result_code == Some(1100) && attempt == 0 {
                        eprintln!("[DevAPI] anisette expired (1100) - refresh...");
                        self.anisette_cache.get(auth, true)?;
                        continue;
                    }

                    // ⭐ Check session expired
                    let http_status = status.as_u16();
                    if is_session_expired_response(http_status, result_code, user_string) {
                        eprintln!("[DevAPI] ⚠️ Session expired: {}", user_string);
                        return Err(anyhow::Error::new(
                            SessionExpiredError::new(user_string.to_string())
                        ));
                    }

                    return Ok(dict);
                }
                Err(e) => {
                    if attempt == 0 {
                        eprintln!("[DevAPI] Loi lan 1: {} - thu lai...", e);
                        self.anisette_cache.get(auth, true)?;
                        continue;
                    }
                    return Err(anyhow!("Request {} that bai: {}", action, e));
                }
            }
        }

        Err(anyhow!("Request {} that bai sau 2 lan", action))
    }

    pub fn request_json(
        &mut self,
        auth: &mut AnisetteClient,
        method_override: &str,
        url: &str,
        query: &str,
    ) -> Result<serde_json::Value> {
        let headers = self.auth_headers_json(auth, true)?;

        let resp = self
            .client
            .post(url)
            .headers(headers)
            .header("X-HTTP-Method-Override", method_override)
            .json(&serde_json::json!({ "urlEncodedQueryParams": query }))
            .send()?;

        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("JSON API {} that bai: {}", url, status));
        }

        let bytes = resp.bytes()?;

        // Empty body (204, hoặc 200 với 0 bytes) = OK, trả Null
        if bytes.is_empty() {
            return Ok(serde_json::Value::Null);
        }

        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!(
                "JSON parse fail: {} - first 200: {}",
                e,
                String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
            ))?;
        Ok(json)
    }
}

pub(crate) fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
