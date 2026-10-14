// src/constants.rs
use std::path::PathBuf;

pub const ANISETTE_URL: &str = "https://ani.sidestore.io";
pub const ANISETTE_FALLBACK: &[&str] = &[
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
];

pub const USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
pub const XCODE_UA: &str = "akd/1.0 CFNetwork/808.1.4";
// Cấu hình chuẩn từ isideload: Pixel 7 (Android 14) + AuthKit akd
// Khớp 100% chữ ký RINFO: 17106176 của Anisette v3 và có đầy đủ thẩm quyền GrandSlam
pub const DEFAULT_CLIENT_INFO: &str =
    ""<Pixel 8 Pro> <Android;14;UP1A.231005.007> <com.apple.AuthKit/1 (com.apple.android.music/4.6.0 (1320)>",

pub const GSA_URL: &str = "https://gsa.apple.com/grandslam/GsService2";
pub const GSA_VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
pub const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
pub const PHONE_VERIFY_URL: &str = "https://gsa.apple.com/auth/verify/phone";
pub const PHONE_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";

pub const APP_XCODE_AUTH: &str = "com.apple.gs.xcode.auth";

pub const FALLBACK_IOS_CLIENT_INFO: &str =
    "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

/// Client-Info chuẩn chính chủ Apple Developer App trên iOS 17.6 cho Developer Services API
pub const DEVELOPER_CLIENT_INFO: &str =
    "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Developer/10.4 (10.4.0)>";
pub const DEVELOPER_USER_AGENT: &str =
    "Developer/10.4 (com.apple.Developer; build:10.4.0; iOS 17.6.1) Alamofire/5.4.0";

pub fn cookie_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".fortiva").join("cookies.enc")
}

/// Chuẩn hóa Client-Info né lỗi -80045 (Apple GSA update 12-14/10/2026)
pub fn fix_client_info(raw_ci: &str) -> String {
    if raw_ci.is_empty() {
        return DEFAULT_CLIENT_INFO.to_string();
    }
    // Apple GSA siết chặt: Nếu khai báo macOS từ server Anisette chạy trên Linux/Docker
    // hoặc có com.apple.dt.Xcode, máy chủ sẽ trả về lỗi -80045 do lệch vân tay phần cứng.
    // Tự động patch sang profile Pixel 7 AuthKit akd (chuẩn isideload) để bypass 100% và tương thích Xcode auth.
    if raw_ci.contains("macOS") {
        return DEFAULT_CLIENT_INFO.to_string();
    }
    if raw_ci.contains("com.apple.dt.Xcode") {
        let fixed = raw_ci.replace("com.apple.dt.Xcode", "com.apple.akd/1.0");
        return fixed;
    }
    raw_ci.to_string()
}
