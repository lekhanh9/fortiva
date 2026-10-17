// src/auth/twofa/trusted.rs
use anyhow::Result;
use plist::Value;
use reqwest::header::HeaderValue;
use std::time::Duration;

use super::TwoFAHandler;
use crate::auth::anisette::AnisetteClient;
use crate::constants::{GSA_VALIDATE_URL, TRUSTED_DEVICE_URL};

pub struct TrustedDeviceHandler;

impl TrustedDeviceHandler {
    pub fn handle(
        &self,
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        already_sent: bool,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
    ) -> Result<bool> {
        let headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;

        // Nếu Apple đã tự động gửi push (HSC 409 theo chuẩn isideload)
        if already_sent {
            println!("[2fa] 📱 Apple đã tự động gửi mã xác minh 2FA tới thiết bị của bạn!");
        } else {
            println!("[2fa] Đang gửi yêu cầu push mã 2FA tới thiết bị tin cậy...");
            let mut push_ok = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    std::thread::sleep(Duration::from_secs(2));
                }

                eprintln!("[DBG-RUST-2FA] === Attempt {}/3 ===", attempt + 1);
                match twofa
                    .client
                    .get(TRUSTED_DEVICE_URL)
                    .headers(headers.clone())
                    .timeout(Duration::from_secs(15))
                    .send()
                {
                    Ok(resp) => {
                        let code = resp.status().as_u16();
                        if code == 200 || code == 412 {
                            println!("[2fa] Push sent (HTTP {})", code);
                            push_ok = true;
                            break;
                        }
                        println!("[2fa] HTTP {} (attempt {}/3)", code, attempt + 1);
                    }
                    Err(e) => {
                        eprintln!("[DBG-RUST-2FA] error: {}", e);
                    }
                }
            }

            if !push_ok {
                eprintln!("[DBG-RUST-2FA] Push không phản hồi 200/412, vẫn mở prompt nhập mã.");
            }
        }

        // ============================================================
        //  Vòng lặp nhập mã & verify (cho phép thử lại tối đa 3 lần nếu sai mã -21669)
        // ============================================================
        for attempt in 1..=3 {
            let prompt = if attempt == 1 {
                "[2fa] Nhập mã 6 số hiển thị trên iPhone/iPad: "
            } else {
                "[2fa] Nhập lại mã 6 số từ iPhone/iPad: "
            };

            let code = input_func(prompt).trim().to_string();
            if code.is_empty() {
                println!("[2fa] Đã hủy nhập mã.");
                return Ok(false);
            }

            let mut verify_headers = twofa.build_2fa_headers(
                anisette, dsid, idms_token, user_id, device_id,
            )?;
            verify_headers.insert(
                "security-code",
                HeaderValue::from_str(&code)?,
            );

            eprintln!("[DBG-RUST-2FA] === Verify code (lần {}/3) ===", attempt);
            eprintln!("[DBG-RUST-2FA] url={}", GSA_VALIDATE_URL);

            let resp = twofa
                .client
                .post(GSA_VALIDATE_URL)
                .headers(verify_headers)
                .body("")
                .timeout(Duration::from_secs(15))
                .send()?;

            let status = resp.status();
            let body = resp.bytes()?;

            let parsed_plist = plist::from_bytes::<Value>(&body).ok();
            let ec = parsed_plist
                .as_ref()
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("Response").or_else(|| d.get("Status")))
                .and_then(|r| r.as_dictionary())
                .and_then(|d| d.get("Status").and_then(|s| s.as_dictionary()).or(Some(d)))
                .and_then(|d| d.get("ec"))
                .and_then(plist_integer)
                .unwrap_or(0);

            let em = parsed_plist
                .as_ref()
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("Response").or_else(|| d.get("Status")))
                .and_then(|r| r.as_dictionary())
                .and_then(|d| d.get("Status").and_then(|s| s.as_dictionary()).or(Some(d)))
                .and_then(|d| d.get("em"))
                .and_then(|v| v.as_string())
                .unwrap_or("");

            if ec == -21669 {
                println!("[2fa] ❌ Mã xác minh không chính xác (-21669). Vui lòng thử lại!");
                continue;
            }

            if status.is_success() || ec == 0 {
                println!("[2fa] ✅ Xác thực 2FA thành công!");
                return Ok(true);
            } else {
                if !em.is_empty() {
                    eprintln!("[2fa] HTTP lỗi xác thực: {} (ec={}, em={})", status, ec, em);
                } else {
                    let body_preview = String::from_utf8_lossy(&body[..body.len().min(200)]);
                    eprintln!("[2fa] HTTP lỗi xác thực: {} - Body: {}", status, body_preview);
                }
            }
        }

        eprintln!("[2fa] Xác thực 2FA thất bại sau 3 lần thử.");
        Ok(false)
    }
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
