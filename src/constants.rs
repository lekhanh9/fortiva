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

/// Làm sạch Client-Info: đổi com.apple.dt.Xcode thành com.apple.akd
pub fn sanitize_client_info(raw_ci: &str) -> String {
    let trimmed = raw_ci.trim();
    if trimmed.is_empty() {
        return DEFAULT_CLIENT_INFO.to_string();
    }
    if trimmed.contains("com.apple.dt.Xcode") {
        return trimmed.replace("com.apple.dt.Xcode", "com.apple.akd");
    }
    trimmed.to_string()
}

/// Chuẩn hóa Client-Info né lỗi Xcode
pub fn fix_client_info(raw_ci: &str) -> String {
    sanitize_client_info(raw_ci)
}

/// Tự động suy ra User-Agent chuẩn và khớp 100% với chuỗi Client-Info
pub fn match_user_agent_for_client_info(client_info: &str) -> String {
    let ci_lower = client_info.to_lowercase();
    if ci_lower.contains("windows") || ci_lower.contains("itunes") {
        return "akd/1.0 CFNetwork/808.1.4".to_string();
    }
    if ci_lower.contains("android") || ci_lower.contains("pixel") {
        return "akd/1.0 CFNetwork/808.1.4".to_string();
    }
    if client_info.contains("15.") || ci_lower.contains("darwin/24") {
        return "akd/1.0 CFNetwork/1568.100.1 Darwin/24.0.0".to_string();
    }
    if client_info.contains("14.") || ci_lower.contains("darwin/23") {
        return "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0".to_string();
    }
    if client_info.contains("13.") || ci_lower.contains("darwin/22") {
        return "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0".to_string();
    }
    if client_info.contains("12.") || ci_lower.contains("darwin/21") {
        return "akd/1.0 CFNetwork/1335.0.3 Darwin/21.6.0".to_string();
    }
    if ci_lower.contains("ios;18") {
        return "akd/1.0 CFNetwork/1568.100.1 Darwin/24.0.0".to_string();
    }
    if ci_lower.contains("ios;17") {
        return "akd/1.0 CFNetwork/1498.700.2 Darwin/23.6.0".to_string();
    }
    if ci_lower.contains("ios;16") {
        return "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0".to_string();
    }
    if ci_lower.contains("mac") {
        return "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0".to_string();
    }
    "akd/1.0 CFNetwork/808.1.4".to_string()
}


