// src/constants.rs
use std::path::PathBuf;

pub const ANISETTE_URL: &str = "https://ani.sidestore.io";
pub const ANISETTE_FALLBACK: &[&str] = &[
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
];

pub const USER_AGENT: &str = "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0";
pub const XCODE_UA: &str = "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0";
// Giả lập Pixel 8 Pro (Android 14) Apple Music để bypass -80045 và phù hợp môi trường Android
pub const DEFAULT_CLIENT_INFO: &str =
    "<Pixel 8 Pro> <Android;14;UP1A.231005.007> <com.apple.android.music/4.6.0 (1320)>";

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
    // Luôn ưu tiên Android Client-Info để tránh Apple chặn -80045
    DEFAULT_CLIENT_INFO.to_string()
}
