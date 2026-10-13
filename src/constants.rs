// src/constants.rs
use std::path::PathBuf;

pub const ANISETTE_URL: &str = "https://ani.sidestore.io";
pub const ANISETTE_FALLBACK: &[&str] = &[
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
];

pub const USER_AGENT: &str = "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0";
pub const XCODE_UA: &str = "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0";
// Bypass lỗi -80045: giả lập iOS 17.5.1 Client-Info thay cho macOS 13.1
pub const DEFAULT_CLIENT_INFO: &str =
    "<iPhone16,1> <iOS;17.5.1;21F90> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

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

pub fn fix_client_info(_ci: &str) -> String {
    // Luôn ưu tiên iOS 17.5.1 để tránh Apple chặn -80045
    DEFAULT_CLIENT_INFO.to_string()
}
