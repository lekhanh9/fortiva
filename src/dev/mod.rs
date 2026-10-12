// src/dev/mod.rs
pub mod max_certs;         // ← MỚI
pub mod session_helper;
pub mod teams;

mod app_groups;
mod app_ids;
mod certificate;
mod client;
mod devices;
mod json_api;
mod plist_api;

pub use app_groups::AppGroup;
pub use app_ids::{AppId, Profile};
pub use certificate::{cert_matches_account, clear_all_certs, decode_cert_content, parse_expiration_date, CertificateBundle};
pub use client::{
    DevError, DeveloperClient, BASE_URL_QH65B2, BASE_URL_V1, CLIENT_ID, PROTOCOL_VERSION,
    XCODE_VERSION,
};
pub use devices::Device;
pub use max_certs::{handle_max_certs, MaxCertsBehavior};        // ← MỚI
pub use session_helper::{is_session_expired, print_session_expired_help};
