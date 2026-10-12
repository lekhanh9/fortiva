// src/constants.rs
use std::path::PathBuf;

pub const ANISETTE_URL: &str = "https://anisette-v3-server-aexk.onrender.com";
pub const ANISETTE_FALLBACK: &[&str] = &[];

pub const USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
pub const XCODE_UA: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
// Khớp với Python reference (X-Mme-Client-Info)
pub const DEFAULT_CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

pub const GSA_URL: &str = "https://gsa.apple.com/grandslam/GsService2";
pub const GSA_VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
pub const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
pub const PHONE_VERIFY_URL: &str = "https://gsa.apple.com/auth/verify/phone";
pub const PHONE_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";

pub const APP_XCODE_AUTH: &str = "com.apple.gs.xcode.auth";

pub fn cookie_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".fortiva").join("cookies.enc")
}

pub fn fix_client_info(ci: &str) -> String {
    if ci.is_empty() {
        return DEFAULT_CLIENT_INFO.to_string();
    }

    let mut result = String::with_capacity(ci.len());
    let mut rest = ci;

    while let Some(start) = rest.find("(com.apple.dt.Xcode") {
        result.push_str(&rest[..start]);
        if let Some(end) = rest[start..].find(')') {
            result.push_str("(com.apple.akd/1.0)");
            rest = &rest[start + end + 1..];
        } else {
            result.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    result.push_str(rest);
    result.replace("com.apple.dt.Xcode", "com.apple.akd")
}
