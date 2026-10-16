// src/constants.rs
use std::path::PathBuf;

pub const ANISETTE_URL: &str = "https://ani.sidestore.io";
pub const ANISETTE_FALLBACK: &[&str] = &[
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
];

pub const USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
pub const XCODE_UA: &str = "akd/1.0 CFNetwork/808.1.4";
// Cấu hình chuẩn Windows iTunes 12.12.4 (chuẩn SideStore / anisette-v3-server, vượt qua xác thực GSA 100%)
pub const DEFAULT_CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>";

pub const GSA_URL: &str = "https://gsa.apple.com/grandslam/GsService2";
pub const GSA_VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
pub const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
pub const PHONE_VERIFY_URL: &str = "https://gsa.apple.com/auth/verify/phone";
pub const PHONE_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";

pub const APP_XCODE_AUTH: &str = "com.apple.gs.xcode.auth";

pub const FALLBACK_IOS_CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>";

/// Client-Info chuẩn chính chủ Apple Developer App cho Developer Services API
pub const DEVELOPER_CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>";
pub const DEVELOPER_USER_AGENT: &str =
    "akd/1.0 CFNetwork/808.1.4";

pub fn cookie_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".fortiva").join("cookies.enc")
}

/// Chuẩn hóa Client-Info né lỗi -80045 và 503 (Apple GSA update)
pub fn fix_client_info(raw_ci: &str) -> String {
    let trimmed = raw_ci.trim();
    if trimmed.is_empty()
        || trimmed.contains("macOS")
        || trimmed.contains("MacBook")
        || trimmed.contains("com.apple.dt.Xcode")
        || trimmed.contains("Android")
        || trimmed.contains("Pixel")
    {
        return DEFAULT_CLIENT_INFO.to_string();
    }
    trimmed.to_string()
}

