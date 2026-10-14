// src/auth/srp/flow.rs
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};

use hmac::{Hmac, Mac};
use plist::{Dictionary, Value};
use sha2::Sha256;
use std::collections::HashMap;

use super::variant::SrpClient;
use crate::auth::crypto::aes::{decrypt_cbc, decrypt_gcm};
use crate::auth::gsa::GsaClient;
use crate::auth::twofa::TwoFAHandler;
use crate::constants::GSA_VALIDATE_URL;
use crate::AuthResult;
use reqwest::header::HeaderValue;
use std::time::Duration;

const APP_XCODE_AUTH: &str = "com.apple.gs.xcode.auth";


/// Extract data field tu plist::Value.
/// Ho tro ca String (base64) va Data (raw bytes).
fn extract_data_field(value: Option<&Value>, field: &str) -> Result<Vec<u8>> {
    match value {
        Some(Value::String(s)) => {
            
            general_purpose::STANDARD
                .decode(s)
                .with_context(|| format!("Decode {} base64 that bai", field))
        }
        Some(Value::Data(d)) => Ok(d.to_vec()),
        Some(other) => Err(anyhow!(
            "Field '{}' sai type: {:?}. Expected String hoac Data",
            field,
            other
        )),
        None => Err(anyhow!("Response thieu field '{}'", field)),
    }
}

pub struct SrpFlow;

impl SrpFlow {
    pub fn new() -> Self {
        Self
    }

    pub fn authenticate(
        &mut self,
        gsa: &mut GsaClient,
        twofa: &mut TwoFAHandler,
        apple_id: &str,
        password: &str,
        depth: u32,
    ) -> Result<AuthResult> {
        if depth > 0 {
            println!("[srp] Retry sau 2FA (depth={})...", depth);
        }

        let mut srp = SrpClient::new(apple_id, password);
        let a_pub_bytes = srp.a_pub_bytes();

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("A2k".into(), Value::Data(a_pub_bytes));
        params.insert(
            "ps".into(),
            Value::Array(vec![
                Value::String("s2k".into()),
                Value::String("s2k_fo".into()),
            ]),
        );
        params.insert("u".into(), Value::String(apple_id.to_string()));
        params.insert("o".into(), Value::String("init".into()));

        println!("[srp] Gui init request...");
        let init_resp = gsa.request(params, 3).context("GSA init that bai")?;

        let protocol = init_resp
            .get("sp")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thieu 'sp'"))?
            .to_string();

        let salt = extract_data_field(init_resp.get("s"), "s")?;

        let b_pub = extract_data_field(init_resp.get("B"), "B")?;


        // c co the la String hoac Data
        let c = match init_resp.get("c") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Data(d)) => {
                
                general_purpose::STANDARD.encode(d)
            }
            other => return Err(anyhow!("Field 'c' sai type: {:?}", other)),
        };

        let iterations = init_resp
            .get("i")
            .and_then(plist_integer)
            .ok_or_else(|| anyhow!("Response thieu 'i'"))? as u32;



        println!(
            "[srp] Protocol={}, iterations={}, salt_len={}, B_len={}",
            protocol,
            iterations,
            salt.len(),
            b_pub.len()
        );

        let m1 = srp
            .process_challenge(&salt, &b_pub, iterations, &protocol)
            .context("Process SRP challenge that bai")?;

        println!("[srp] M1 computed ({} bytes)", m1.len());

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("c".into(), Value::String(c));
        params.insert("M1".into(), Value::Data(m1));
        params.insert("u".into(), Value::String(apple_id.to_string()));
        params.insert("o".into(), Value::String("complete".into()));

        println!("[srp] Gui complete request...");
        let complete_resp = gsa.request(params, 3).context("GSA complete that bai")?;

        let status = complete_resp
            .get("Status")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Response thieu 'Status'"))?
            .clone();

        if let Some(m2) = complete_resp.get("M2").and_then(|v| v.as_data()) {
            match srp.verify_server_proof(m2) {
                Ok(true) => println!("[srp] M2 verified"),
                Ok(false) => println!("[srp] M2 mismatch"),
                Err(e) => println!("[srp] Khong verify duoc M2: {}", e),
            }
        }

        let session_key = srp
            .session_key()
            .ok_or_else(|| anyhow!("Khong co session key"))?
            .to_vec();

        println!("[srp] Session key OK ({} bytes)", session_key.len());

        let spd_data: Dictionary = if let Some(spd) = complete_resp.get("spd").and_then(|v| v.as_data()) {
            match decrypt_cbc(&session_key, spd) {
                Ok(decrypted) => {
                    let wrapped = crate::auth::gsa::ensure_plist_wrapper(&decrypted);
                    match plist::from_bytes::<Value>(&wrapped) {
                        Ok(val) => val.as_dictionary().cloned().unwrap_or_default(),
                        Err(e) => {
                            println!("[srp] Parse spd that bai: {}", e);
                            Dictionary::new()
                        }
                    }
                }
                Err(e) => {
                    println!("[srp] Decrypt spd CBC that bai: {}", e);
                    Dictionary::new()
                }
            }
        } else {
            Dictionary::new()
        };

        println!("[srp] SPD co {} keys", spd_data.len());
        
        // DEBUG SPD keys
        eprintln!("[DBG-SPD] adsid: {}", spd_data.get("adsid").is_some());
        eprintln!("[DBG-SPD] c: {}", spd_data.get("c").is_some());
        eprintln!("[DBG-SPD] sk: {}", spd_data.get("sk").is_some());
        eprintln!("[DBG-SPD] GsIdmsToken: {}", spd_data.get("GsIdmsToken").is_some());
        eprintln!("[DBG-SPD] idmsToken: {}", spd_data.get("idmsToken").is_some());
        let all_keys: Vec<&str> = spd_data.keys().map(|k| k.as_str()).collect();
        eprintln!("[DBG-SPD] All keys ({}): {:?}", all_keys.len(), all_keys);

        let hsc = status
            .get("hsc")
            .and_then(plist_integer)
            .unwrap_or(200);
        let spd_status = spd_data
            .get("status-code")
            .and_then(plist_integer);
        let spd_authmode = spd_data
            .get("authmode")
            .and_then(|v| v.as_string());
        let status_au = status
            .get("au")
            .and_then(|v| v.as_string());

        eprintln!(
            "[DBG-2FA] Status.hsc={}, SPD.status-code={:?}, Status.au={:?}, SPD.authmode={:?}",
            hsc, spd_status, status_au, spd_authmode
        );

        // Trích xuất au đa tầng: Status -> Response -> SPD (au) -> SPD (authmode)
        let mut auth_type = status
            .get("au")
            .or_else(|| complete_resp.get("au"))
            .or_else(|| spd_data.get("au"))
            .or_else(|| {
                if let Some(am) = spd_authmode {
                    if am != "password" {
                        return spd_data.get("authmode");
                    }
                }
                None
            })
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        // Nếu Apple trả về status-code/hsc 409 (Secondary Auth Required) mà chưa gán auth_type
        if auth_type.is_none() && (hsc == 409 || spd_status == Some(409)) {
            auth_type = Some(
                spd_authmode
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "trustedDeviceSecondaryAuth".to_string()),
            );
        }

        eprintln!("[DBG-AUTH] auth_type = {:?}", auth_type);

        let is_already_sent = hsc == 409 || spd_status == Some(409);

        if let Some(au) = &auth_type {
            if au.contains("SecondaryAuth") || au == "secondaryAuth" || au == "trustedDeviceSecondaryAuth" || au == "smsSecondaryAuth" {
                println!("[srp] Yeu cau 2FA: {}", au);

                if !is_already_sent {
                    println!("[srp] Chờ 2s trước khi gửi 2FA request...");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }

                let dsid = extract_string(&spd_data, &["adsid", "dsid"])
                    .or_else(|| extract_string(&status, &["dsid"]))
                    .ok_or_else(|| anyhow!("Khong lay duoc dsid cho 2FA"))?;

                let idms_token = extract_string(&spd_data, &["GsIdmsToken", "idmsToken"])
                    .or_else(|| extract_string(&status, &["idmsToken"]))
                    .ok_or_else(|| anyhow!("Khong lay duoc idms_token cho 2FA"))?;

                println!("[srp] DSID: {}", dsid);

                let input_func = |prompt: &str| -> String {
                    prompt_interactive_code(prompt)
                };

                let twofa_ok = TwoFAHandler::handle_2fa(
                    twofa,
                    &mut gsa.anisette,
                    au,
                    is_already_sent,
                    &dsid,
                    &idms_token,
                    &gsa.user_id.clone(),
                    &gsa.device_id.clone(),
                    &input_func,
                )?;

                if !twofa_ok {
                    return Err(anyhow!("2FA that bai"));
                }

                if depth >= 1 {
                    println!("[srp] Đã hoàn thành xác thực 2FA.");
                } else {
                    println!("[srp] Xác thực 2FA thành công! Tiếp tục lấy AppToken...");
                }
            }
        }

        let dsid = extract_string(&spd_data, &["adsid", "dsid"]);

        let app_token = if let (Some(adsid), Some(c2), Some(sk), Some(idms)) = (
            extract_string(&spd_data, &["adsid"]),
            spd_data.get("c").cloned(),
            extract_data_flexible(&spd_data, "sk"),
            extract_string(&spd_data, &["GsIdmsToken", "idmsToken"]),
        ) {
            match self.fetch_app_token(gsa, twofa, &adsid, &c2, &idms, &sk, &session_key, true) {
                Ok(Some(t)) => {
                    println!("[srp] App token OK");
                    Some(t)
                }
                Ok(None) => None,
                Err(e) => {
                    println!("[srp] Fetch app token that bai: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(AuthResult {
            user_id: apple_id.to_string(),
            authenticated: true,
            dsid,
            session_token: app_token,
            needs_2fa: false,
        })
    }

    fn fetch_app_token(
        &self,
        gsa: &mut GsaClient,
        twofa: &mut TwoFAHandler,
        adsid: &str,
        c: &Value,
        idms_token: &str,
        sk: &[u8],
        session_key: &[u8],
        allow_2fa: bool,
    ) -> Result<Option<String>> {
        eprintln!("[DBG-APPTOKEN] === fetch_app_token ===");
        eprintln!("[DBG-APPTOKEN] adsid: {}", &adsid[..adsid.len().min(20)]);
        eprintln!("[DBG-APPTOKEN] c type: {:?}", std::mem::discriminant(c));
        eprintln!("[DBG-APPTOKEN] idms_token len: {}", idms_token.len());
        eprintln!("[DBG-APPTOKEN] sk len: {}", sk.len());
        eprintln!("[DBG-APPTOKEN] session_key len: {}", session_key.len());

        const APP: &str = APP_XCODE_AUTH;

        let mut mac = Hmac::<Sha256>::new_from_slice(sk).map_err(|e| anyhow!("HMAC init: {}", e))?;
        mac.update(b"apptokens");
        mac.update(adsid.as_bytes());
        mac.update(APP.as_bytes());
        let checksum = mac.finalize().into_bytes().to_vec();

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("u".into(), Value::String(adsid.to_string()));
        params.insert("app".into(), Value::Array(vec![Value::String(APP.to_string())]));
        params.insert("c".into(), c.clone());
        params.insert("t".into(), Value::String(idms_token.to_string()));
        params.insert("checksum".into(), Value::Data(checksum));
        params.insert("o".into(), Value::String("apptokens".into()));

        println!("[srp] Gui apptokens request...");
        let resp = gsa.request(params, 1)
            .map_err(|e| {
                eprintln!("[DBG-APPTOKEN] ❌ request failed: {}", e);
                e
            })?;
        eprintln!("[DBG-APPTOKEN] ✅ response keys: {:?}", resp.keys().collect::<Vec<_>>());

        let ec = resp
            .get("Status")
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get("ec"))
            .and_then(plist_integer)
            .unwrap_or(0);

        if ec == -22411 && allow_2fa {
            println!("\n[srp] 📱 Apple đã gửi mã xác minh 2FA (-22411) tới thiết bị Apple của bạn!");
            for attempt in 1..=3 {
                let prompt = if attempt == 1 {
                    "[2fa] Nhập mã 6 số hiển thị trên iPhone/iPad: "
                } else {
                    "[2fa] Nhập lại mã 6 số từ iPhone/iPad: "
                };
                let code = prompt_interactive_code(prompt);

                if code.is_empty() || code.eq_ignore_ascii_case("cancel") || code.eq_ignore_ascii_case("q") {
                    println!("[2fa] Đã hủy nhập mã 2FA.");
                    break;
                }

                println!("[2fa] Đang gửi mã 2FA xác thực với Apple...");
                let mut verify_headers = twofa.build_2fa_headers(
                    &mut gsa.anisette,
                    adsid,
                    idms_token,
                    &gsa.user_id,
                    &gsa.device_id,
                )?;
                verify_headers.insert(
                    "security-code",
                    HeaderValue::from_str(&code)?,
                );

                let v_resp = twofa
                    .client
                    .post(GSA_VALIDATE_URL)
                    .headers(verify_headers)
                    .body("")
                    .timeout(Duration::from_secs(15))
                    .send();

                match v_resp {
                    Ok(r) if r.status().is_success() => {
                        let bytes = r.bytes().unwrap_or_default();
                        if let Ok(val) = plist::from_bytes::<Value>(&bytes) {
                            let ec = val
                                .as_dictionary()
                                .and_then(|d| d.get("Response"))
                                .and_then(|r| r.as_dictionary())
                                .and_then(|d| d.get("Status"))
                                .and_then(|s| s.as_dictionary())
                                .and_then(|d| d.get("ec"))
                                .and_then(plist_integer)
                                .unwrap_or(0);
                            if ec == -21669 {
                                println!("[2fa] ❌ Mã xác minh không chính xác (-21669). Vui lòng thử lại!");
                                continue;
                            }
                        }
                        println!("[2fa] ✅ Xác thực 2FA thành công! Đang lấy AppToken...");
                        std::thread::sleep(Duration::from_secs(2));
                        return self.fetch_app_token(
                            gsa,
                            twofa,
                            adsid,
                            c,
                            idms_token,
                            sk,
                            session_key,
                            false,
                        );
                    }
                    Ok(r) => {
                        eprintln!("[2fa] Xác thực 2FA thất bại: HTTP {}", r.status());
                    }
                    Err(e) => {
                        eprintln!("[2fa] Lỗi kết nối xác thực 2FA: {}", e);
                    }
                }
            }
        }

        let et = resp
            .get("et")
            .and_then(|v| v.as_data())
            .ok_or_else(|| {
                eprintln!("[DBG-APPTOKEN] ❌ Response thiếu 'et'");
                eprintln!("[DBG-APPTOKEN] Response đầy đủ: {:?}", resp);
                anyhow!("Response thieu 'et'")
            })?;
        eprintln!("[DBG-APPTOKEN] ✅ et len: {}", et.len());

        let decrypted = decrypt_gcm(sk, et)
            .map_err(|e| {
                eprintln!("[DBG-APPTOKEN] ❌ decrypt_gcm failed: {}", e);
                e
            })
            .context("Decrypt et GCM that bai")?;
        eprintln!("[DBG-APPTOKEN] ✅ decrypted len: {}", decrypted.len());

        let wrapped_et = crate::auth::gsa::ensure_plist_wrapper(&decrypted);
        let plist_val: Value = plist::from_bytes(&wrapped_et).context("Parse et plist that bai")?;

        let app_tokens = plist_val
            .as_dictionary()
            .and_then(|d| d.get("t"))
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("et thieu 't'"))?;

        let token_info = app_tokens
            .get(APP)
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Khong co token cho {}", APP))?;

        let token = token_info
            .get("token")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        Ok(token)
    }
}

fn extract_string(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = dict.get(*k) {
            match v {
                Value::String(s) => return Some(s.to_string()),
                Value::Data(d) => {
                    // Python plist co the tra bytes -> thu UTF-8, fallback base64
                    if let Ok(s) = String::from_utf8(d.to_vec()) {
                        return Some(s);
                    }
                    return Some(general_purpose::STANDARD.encode(d));
                }
                _ => {}
            }
        }
    }
    None
}

/// Lay data linh hoat: Data hoac String (base64 hoac raw)
fn extract_data_flexible(dict: &Dictionary, key: &str) -> Option<Vec<u8>> {
    dict.get(key).and_then(|v| match v {
        Value::Data(d) => Some(d.to_vec()),
        Value::String(s) => {
            general_purpose::STANDARD
                .decode(s)
                .ok()
                .or_else(|| Some(s.as_bytes().to_vec()))
        }
        _ => None,
    })
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}

fn prompt_interactive_code(prompt_msg: &str) -> String {
    use std::io::{self, BufRead, Write};
    print!("{}", prompt_msg);
    let _ = io::stdout().flush();

    #[cfg(unix)]
    {
        if let Ok(tty_file) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
            let mut reader = std::io::BufReader::new(tty_file);
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
                line.clear();
            }
        }
    }

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buf = String::new();
    while handle.read_line(&mut buf).is_ok() {
        let trimmed = buf.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
        buf.clear();
    }
    String::new()
}

