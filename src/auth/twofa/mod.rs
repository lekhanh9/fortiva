// src/auth/twofa/mod.rs
mod sms;
mod trusted;

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};

use crate::auth::anisette::AnisetteClient;
use crate::constants::{fix_client_info, APP_XCODE_AUTH, DEFAULT_CLIENT_INFO, XCODE_UA};

pub use sms::SmsHandler;
pub use trusted::TrustedDeviceHandler;

pub struct TwoFAHandler {
    pub client: reqwest::blocking::Client,
    pub client_info: String,
}

impl TwoFAHandler {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .no_proxy()
            .http1_only()
            .build()
            .expect("reqwest client");

        Self {
            client,
            client_info: DEFAULT_CLIENT_INFO.to_string(),
        }
    }

    pub fn build_2fa_headers(
        &mut self,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        let identity_token = general_purpose::STANDARD
            .encode(format!("{}:{}", dsid, idms_token).as_bytes());

        // Fetch anisette trước để update client_info
        let anisette_data = anisette.fetch(false)?;

        if let Some(ci) = anisette_data.get("X-MMe-Client-Info") {
            self.client_info = fix_client_info(ci);
        }
        if self.client_info.contains("Xcode") || self.client_info.contains("macOS") {
            self.client_info = fix_client_info(&self.client_info);
        }
        if self.client_info.is_empty() {
            self.client_info = DEFAULT_CLIENT_INFO.to_string();
        }

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(USER_AGENT, HeaderValue::from_static(XCODE_UA));
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.insert(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token)?,
        );
        headers.insert("X-Apple-App-Info", HeaderValue::from_static(APP_XCODE_AUTH));
        headers.insert("X-Xcode-Version", HeaderValue::from_static("14.2 (14C18)"));
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
        headers.insert("X-Apple-I-DSID", HeaderValue::from_str(dsid)?);

        let meta = AnisetteClient::get_meta_headers(user_id, device_id);
        for (k, v) in meta {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                headers.insert(name, value);
            }
        }

        for key in [
            "X-Apple-I-MD",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id",
            "X-Apple-I-Client-Time",
        ] {
            if let Some(v) = anisette_data.get(key) {
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, value);
                }
            }
        }

        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&general_purpose::STANDARD.encode(dsid.as_bytes()))?,
        );

        Ok(headers)
    }

    pub fn handle_2fa(
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        auth_type: &str,
        already_sent: bool,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
    ) -> Result<bool> {
        match auth_type {
            "trustedDeviceSecondaryAuth" | "secondaryAuth" => {
                let trusted = TrustedDeviceHandler;
                match trusted.handle(
                    twofa, anisette, already_sent, dsid, idms_token, user_id, device_id, input_func,
                ) {
                    Ok(true) => return Ok(true),
                    Ok(false) => println!("[2fa] Trusted device fail, fallback SMS"),
                    Err(e) => println!("[2fa] Trusted device error: {}, fallback SMS", e),
                }

                let sms = SmsHandler;
                sms.handle(twofa, anisette, dsid, idms_token, user_id, device_id, input_func)
            }
            "smsSecondaryAuth" => {
                println!("[2fa] Trying SMS first...");
                let sms = SmsHandler;
                match sms.handle(
                    twofa, anisette, dsid, idms_token, user_id, device_id, input_func,
                ) {
                    Ok(true) => return Ok(true),
                    Ok(false) => println!("[2fa] SMS fail, fallback trusted device"),
                    Err(e) => println!("[2fa] SMS error: {}, fallback trusted device", e),
                }

                let trusted = TrustedDeviceHandler;
                trusted.handle(twofa, anisette, false, dsid, idms_token, user_id, device_id, input_func)
            }
            other => Err(anyhow!("2FA type not supported: {}", other)),
        }
    }
}
