// tests/test_cert_lifecycle.rs
use fortiva::usb::is_valid_udid;
use fortiva::dev::{cert_matches_account, parse_expiration_date, CertificateBundle};
use fortiva::sideload::signer::extract_entitlements_xml_string;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::x509::{X509, X509NameBuilder};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use base64::{Engine as _, engine::general_purpose};

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

#[test]
fn test_parse_expiration_date() {
    // 1. Standard RFC3339
    let dt1 = parse_expiration_date("2025-05-01T12:00:00Z").expect("parse rfc3339 Z");
    assert_eq!(dt1.to_rfc3339(), "2025-05-01T12:00:00+00:00");

    // 2. RFC3339 with offset +00:00
    let dt2 = parse_expiration_date("2025-05-01T12:00:00.000+00:00").expect("parse rfc3339 colon");
    assert_eq!(dt2.timestamp(), dt1.timestamp());

    // 3. Apple format with +0000 (no colon)
    let dt3 = parse_expiration_date("2025-05-01T12:00:00.000+0000").expect("parse no colon");
    assert_eq!(dt3.timestamp(), dt1.timestamp());

    // 4. Non-zero offset +0500 (17:00 +0500 is 12:00 UTC)
    let dt4 = parse_expiration_date("2025-05-01T17:00:00+0500").expect("parse +0500");
    assert_eq!(dt4.timestamp(), dt1.timestamp());

    // 5. Naive ISO datetime
    let dt5 = parse_expiration_date("2025-05-01T12:00:00").expect("parse naive");
    assert_eq!(dt5.timestamp(), dt1.timestamp());

    // 6. Date only
    let dt6 = parse_expiration_date("2025-05-01").expect("parse date only");
    assert_eq!(dt6.format("%Y-%m-%d").to_string(), "2025-05-01");

    // 7. Invalid or empty
    assert!(parse_expiration_date("").is_none());
    assert!(parse_expiration_date("   ").is_none());
    assert!(parse_expiration_date("invalid-date-string").is_none());
}

#[test]
fn test_bundle_expired_with_real_x509() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Fortiva").unwrap();
    let name = name.build();

    // 1. Expired certificate (in 2010)
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let past_start = Asn1Time::from_unix(1262304000).unwrap(); // 2010-01-01
    let past_end = Asn1Time::from_unix(1293840000).unwrap();   // 2011-01-01
    builder.set_not_before(&past_start).unwrap();
    builder.set_not_after(&past_end).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let expired_cert = builder.build();
    let expired_pem = String::from_utf8(expired_cert.to_pem().unwrap()).unwrap();

    let expired_bundle = CertificateBundle {
        certificate_id: Some("CERT_EXPIRED".to_string()),
        cert_content_b64: Some(expired_pem),
        private_key_pem: String::new(),
        csr_pem: String::new(),
        machine_id: "MACHINE1".to_string(),
        apple_id: "test@example.com".to_string(),
        team_id: "TEAM1".to_string(),
    };
    assert!(expired_bundle.is_expired(), "Expired certificate must return true for is_expired");

    // 2. Future valid certificate (until 2038)
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let now_ts = fortiva::session::now() as i64;
    let valid_start = Asn1Time::from_unix(now_ts - 3600).unwrap();
    let valid_end = Asn1Time::from_unix(now_ts + 30 * 86400).unwrap();
    builder.set_not_before(&valid_start).unwrap();
    builder.set_not_after(&valid_end).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let valid_cert = builder.build();
    let valid_der = valid_cert.to_der().unwrap();
    let valid_b64 = format!("  \n{}\n  ", general_purpose::STANDARD.encode(&valid_der));

    let valid_bundle = CertificateBundle {
        certificate_id: Some("CERT_VALID".to_string()),
        cert_content_b64: Some(valid_b64),
        private_key_pem: String::new(),
        csr_pem: String::new(),
        machine_id: "MACHINE1".to_string(),
        apple_id: "test@example.com".to_string(),
        team_id: "TEAM1".to_string(),
    };
    assert!(!valid_bundle.is_expired(), "Valid future certificate must return false for is_expired");

    // 3. Corrupted certificate content
    let corrupted_bundle = CertificateBundle {
        certificate_id: Some("CERT_CORRUPT".to_string()),
        cert_content_b64: Some("not-valid-base64-or-pem".to_string()),
        private_key_pem: String::new(),
        csr_pem: String::new(),
        machine_id: "MACHINE1".to_string(),
        apple_id: "test@example.com".to_string(),
        team_id: "TEAM1".to_string(),
    };
    assert!(corrupted_bundle.is_expired(), "Corrupted cert must be treated as expired/invalid");
}

#[test]
fn test_auto_revoke_candidates_ordering() {
    let certs_json = serde_json::json!([
        {
            "id": "CERT_FUTURE_1",
            "attributes": {
                "expirationDate": "2025-06-01T12:00:00Z"
            }
        },
        {
            "id": "CERT_OLDEST",
            "attributes": {
                "expirationDate": "2024-01-01T17:00:00+0500" // Earlier than 2024-06
            }
        },
        {
            "id": "CERT_MIDDLE",
            "attributes": {
                "expirationDate": "2024-06-01T12:00:00.000+0000"
            }
        },
        {
            "id": "CERT_NO_DATE",
            "attributes": {
                "expirationDate": ""
            }
        }
    ]);

    let certs = certs_json.as_array().unwrap();
    let mut candidates: Vec<&serde_json::Value> = certs.iter().collect();
    candidates.sort_by_key(|c| {
        c.get("attributes")
            .and_then(|a| a.get("expirationDate"))
            .and_then(|e| e.as_str())
            .and_then(parse_expiration_date)
            .map(|dt| dt.timestamp())
            .unwrap_or(i64::MAX)
    });

    let ids: Vec<&str> = candidates
        .iter()
        .map(|c| c.get("id").unwrap().as_str().unwrap())
        .collect();

    assert_eq!(ids[0], "CERT_OLDEST");
    assert_eq!(ids[1], "CERT_MIDDLE");
    assert_eq!(ids[2], "CERT_FUTURE_1");
    assert_eq!(ids[3], "CERT_NO_DATE");
}

#[test]
fn test_extract_entitlements_app_group_injection() {
    let raw_plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>TestApp</string>
    <key>Entitlements</key>
    <dict>
        <key>get-task-allow</key>
        <true/>
    </dict>
</dict>
</plist>"#;

    // 1. Without group
    let ent_xml = extract_entitlements_xml_string(raw_plist, None).unwrap();
    assert!(ent_xml.contains("get-task-allow"));
    assert!(!ent_xml.contains("application-groups"));

    // 2. With app group
    let ent_xml_with_group = extract_entitlements_xml_string(raw_plist, Some("group.com.fortiva.app")).unwrap();
    assert!(ent_xml_with_group.contains("com.apple.security.application-groups"));
    assert!(ent_xml_with_group.contains("group.com.fortiva.app"));

    // 3. Re-inject same group shouldn't duplicate
    let dummy_profile = format!(
        "<plist><dict><key>Entitlements</key>{}</dict></plist>",
        ent_xml_with_group
            .replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "")
            .replace("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">", "")
    );
    let re_injected = extract_entitlements_xml_string(dummy_profile.as_bytes(), Some("group.com.fortiva.app")).unwrap();
    let count = re_injected.matches("group.com.fortiva.app").count();
    assert_eq!(count, 1, "App Group should not be duplicated in entitlements");
}
