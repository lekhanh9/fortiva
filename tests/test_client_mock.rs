// tests/test_client_mock.rs
use fortiva::dev::DeveloperClient;

#[test]
fn test_client_creation() {
    let client = DeveloperClient::new(
        "12345678".to_string(),
        "token_abc".to_string(),
    );
    assert!(client.is_ok());
    let c = client.unwrap();
    assert_eq!(c.dsid, "12345678");
    assert_eq!(c.session_token, "token_abc");
    assert!(c.team_id.is_none());
}

#[test]
fn test_set_team() {
    let mut client = DeveloperClient::new(
        "12345678".to_string(),
        "token_abc".to_string(),
    ).unwrap();

    client.set_team("TEAM123456".to_string());
    assert_eq!(client.team_id, Some("TEAM123456".to_string()));
}

// Test đầy đủ với mock server sẽ phức tạp vì cần override BASE_URL
// Cách tốt hơn: thêm constructor cho phép custom base_url