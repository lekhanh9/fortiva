// tests/test_cert_lifecycle.rs
use fortiva::usb::is_valid_udid;
use fortiva::dev::{cert_matches_account, CertificateBundle};

#[test]
fn test_udid_validation() {
    // 40 hex chars
    assert!(is_valid_udid("1234567890abcdef1234567890abcdef12345678"));
    // 25 chars with hyphen at index 8
    assert!(is_valid_udid("00008030-001234567890ABCD"));
    // invalid length
    assert!(!is_valid_udid("1234"));
    // invalid hyphen pos
    assert!(!is_valid_udid("0000803-0001234567890ABCD"));
    // invalid hex chars
    assert!(!is_valid_udid("00008030-001234567890ABCG"));
}

#[test]
fn test_bundle_expired_detection() {
    let bundle = CertificateBundle {
        certificate_id: Some("CERT123".to_string()),
        cert_content_b64: None,
        private_key_pem: String::new(),
        csr_pem: String::new(),
        machine_id: "MACHINE1".to_string(),
        apple_id: "test@example.com".to_string(),
        team_id: "TEAM1".to_string(),
    };
    // No cert content means not expired according to x509 check
    assert!(!bundle.is_expired());
}

#[test]
fn test_cert_matches_nonexistent() {
    // Non-existent certs dir returns false
    assert!(!cert_matches_account("nonexistent@example.com", "NOTEAM"));
}
