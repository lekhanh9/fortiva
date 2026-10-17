// src/sideload/entitlements.rs
use anyhow::{anyhow, Context, Result};
use plist::{Dictionary, Value};

use super::application::SpecialApp;

/// Trích entitlements từ provisioning profile.
pub fn extract_entitlements(
    profile_data: &[u8],
    special: &Option<SpecialApp>,
    team_id: &str,
    new_bundle_id: &str,
) -> Result<Dictionary> {
    // Tìm <plist ...> ... </plist> trong CMS wrapper
    let start = find_subsequence(profile_data, b"<plist")
        .ok_or_else(|| anyhow!("Không tìm thấy <plist trong profile"))?;
    let end = rfind_subsequence(profile_data, b"</plist>")
        .ok_or_else(|| anyhow!("Không tìm thấy </plist> trong profile"))?
        + b"</plist>".len();

    let plist_data = &profile_data[start..end];
    let plist: Value = plist::from_bytes(plist_data)
        .context("Parse profile plist thất bại")?;

    let mut entitlements = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Profile plist không phải dict"))?
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("Profile thiếu Entitlements"))?
        .clone();

    // Special case: LiveContainer / SideStoreLc cần 128 keychain groups
    let is_livecontainer = matches!(
        special,
        Some(SpecialApp::SideStoreLc) | Some(SpecialApp::LiveContainer)
    ) || new_bundle_id.to_lowercase().contains("livecontainer");

    let new_app_id = format!("{}.{}", team_id, new_bundle_id);
    entitlements.insert(
        "application-identifier".to_string(),
        Value::String(new_app_id.clone()),
    );
    println!("[entitlements] Override app-id: {}", new_app_id);

    if is_livecontainer {
        println!("[entitlements] 🔑 Thêm 128 Keychain Access Groups cho LiveContainer...");
        let mut keychain_groups = vec![
            Value::String(new_app_id.clone()),
            Value::String(format!("{}.com.kdt.livecontainer.shared", team_id)),
            Value::String(format!("{}.com.kdt.livecontainer", team_id)),
        ];

        for i in 1..=128 {
            keychain_groups.push(Value::String(format!(
                "{}.com.kdt.livecontainer.shared.{}",
                team_id, i
            )));
        }

        entitlements.insert(
            "keychain-access-groups".to_string(),
            Value::Array(keychain_groups),
        );
        println!("[entitlements] ✅ 128 keychain-access-groups đã được tạo thành công");
    } else {
        // keychain-access-groups[0] phải = new_app_id (giữ wildcard nếu có)
        let should_override = match entitlements.get("keychain-access-groups") {
            Some(Value::Array(groups)) if !groups.is_empty() => {
                match &groups[0] {
                    Value::String(s) => s != "*" && !s.ends_with(".*"),
                    _ => true,
                }
            }
            _ => true,
        };

        if should_override {
            entitlements.insert(
                "keychain-access-groups".to_string(),
                Value::Array(vec![Value::String(new_app_id.clone())]),
            );
        }
    }

    Ok(entitlements)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
}