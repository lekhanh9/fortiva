// src/main.rs
use anyhow::{anyhow, Context, Result};
use fortiva::auth::anisette::AnisetteClient;
use fortiva::auth::gsa::GsaClient;
use fortiva::auth::twofa::TwoFAHandler;
use fortiva::ui::{log, menu, progress, spinner, theme};
use fortiva::session::Session;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

// ============================================================
//  INPUT HELPERS
// ============================================================

fn prompt_text(label: &str) -> String {
    print!("  {} {} ", theme::primary("»"), label);
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    io::stdin().lock().read_until(b'\n', &mut buf).ok();
    String::from_utf8_lossy(&buf).trim().to_string()
}

fn prompt_password(label: &str) -> String {
    let prompt = format!("  {} {} ", theme::primary("»"), label);
    match rpassword::prompt_password(prompt) {
        Ok(s) => s,
        Err(_) => prompt_text(label),
    }
}

fn prompt_yn(label: &str) -> bool {
    let ans = prompt_text(label);
    matches!(ans.to_lowercase().as_str(), "y" | "yes")
}

fn pause() {
    print!("\n  {} ", theme::muted("Nhấn Enter để tiếp tục..."));
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    let _ = io::stdin().lock().read_until(b'\n', &mut buf);
}

fn shellexpand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    s.to_string()
}

// ============================================================
//  MENU CHOICE — tự clear trước khi hiện
// ============================================================

fn prompt_choice() -> String {
    menu::print_menu();
    print!("  {} Chọn (1-8 hoặc 0): ", theme::bold_primary("?"));
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    io::stdin().lock().read_until(b'\n', &mut buf).ok();
    String::from_utf8_lossy(&buf).trim().to_string()
}

/// Vẽ lại toàn bộ màn hình: logo + status + menu.
fn redraw_home() {
    theme::clear_screen();
    menu::print_logo();
    let iphone = get_iphone_status();
    let account = get_account_status();
    menu::print_status_with_account(&iphone, &account);
}

// ============================================================
//  STATUS
// ============================================================


fn get_iphone_status() -> String {
    let usbmuxd_ok = std::process::Command::new("pgrep")
        .args(["-f", "usbmuxd"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !usbmuxd_ok {
        return theme::muted("🔴 DISCONNECTED (usbmuxd chưa chạy)");
    }

    match std::process::Command::new("idevice_id").arg("-l").output() {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            let udid = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if udid.len() >= 8 {
                theme::success(&format!("🟢 CONNECTED (UDID: {}...)", &udid[..8]))
            } else {
                theme::success("🟢 CONNECTED")
            }
        }
        _ => theme::muted("🔴 DISCONNECTED"),
    }
}

// ============================================================
//  FEATURE 1: LOGIN
// ============================================================


// ============================================================
//  SESSION MANAGEMENT (moi)
// ============================================================

use fortiva::dev::{is_session_expired, print_session_expired_help};

/// Lấy session, nếu chưa login hoặc hết hạn thì hỏi đăng nhập luôn (kiểu iLoader)
fn ensure_or_prompt_session() -> Result<Session> {
    match Session::load()? {
        Some(s) if !s.is_expired() => Ok(s),
        Some(_) => {
            log::warn("Session Apple ID đã hết hạn (quá 7 ngày). Cần đăng nhập lại.");
            if prompt_yn("Đăng nhập lại Apple ID ngay bây giờ? (y/n):") {
                cmd_login_apple_id()?;
                Session::load()?
                    .filter(|sess| !sess.is_expired())
                    .ok_or_else(|| anyhow!("Đăng nhập chưa hoàn tất"))
            } else {
                Err(anyhow!("Cần đăng nhập để tiếp tục"))
            }
        }
        None => {
            log::warn("Chưa đăng nhập tài khoản Apple ID.");
            if prompt_yn("Đăng nhập Apple ID ngay bây giờ? (y/n):") {
                cmd_login_apple_id()?;
                Session::load()?
                    .ok_or_else(|| anyhow!("Đăng nhập chưa hoàn tất"))
            } else {
                Err(anyhow!("Chưa đăng nhập"))
            }
        }
    }
}

fn ensure_session() -> Result<Session> {
    ensure_or_prompt_session()
}

/// Wrapper: chay command + xu ly session expired.
#[allow(dead_code)]
fn with_session<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Session) -> Result<T>,
{
    let session = ensure_session()?;

    match f(&session) {
        Ok(v) => Ok(v),
        Err(e) => {
            if is_session_expired(&e) {
                print_session_expired_help();
            }
            Err(e)
        }
    }
}

/// Account status cho UI.
fn get_account_status() -> String {
    match Session::load() {
        Ok(Some(s)) => {
            if s.is_expired() {
                theme::warning(&format!("Account: {} (hết hạn)", s.apple_id))
            } else {
                let team_info = s.team_name.as_deref().unwrap_or(s.team_id.as_deref().unwrap_or(""));
                if !team_info.is_empty() {
                    theme::success(&format!("Account: {} [{}]", s.apple_id, team_info))
                } else {
                    theme::success(&format!("Account: {}", s.apple_id))
                }
            }
        }
        _ => theme::muted("Account: Chưa đăng nhập"),
    }
}

fn cmd_login_apple_id() -> Result<()> {
    theme::clear_screen();
    log::header("LOGIN APPLE ID");

    let apple_id = prompt_text("Apple ID:");
    if apple_id.is_empty() {
        return Err(anyhow!("Apple ID không được rỗng"));
    }

    let password = prompt_password("Password:");
    if password.is_empty() {
        return Err(anyhow!("Password không được rỗng"));
    }

    println!();
    let sp = spinner::new("Đang lấy anisette headers...");
    let mut anisette = AnisetteClient::new(None);
    match anisette.fetch(false) {
        Ok(h) => {
            sp.finish_and_clear();
            log::success(&format!("Anisette OK ({} headers)", h.len()));
        }
        Err(e) => {
            sp.finish_and_clear();
            log::error(&format!("Anisette thất bại: {}", e));
            return Err(e);
        }
    }

    let user_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();

    let mut gsa = GsaClient::new(anisette, user_id.clone(), device_id.clone());
    let mut twofa = TwoFAHandler::new();

    println!();
    log::info("Bắt đầu SRP authentication...");
    println!();

    let mut srp = fortiva::auth::srp::SrpFlow::new();

    match srp.authenticate(&mut gsa, &mut twofa, &apple_id, &password, 0) {
        Ok(result) => {
            if result.authenticated {
                let token_opt = result.session_token.as_ref().filter(|t| !t.is_empty());
                if token_opt.is_none() {
                    let err_lines = vec![
                        "Xác thực SRP hoàn tất nhưng chưa lấy được Xcode AppToken.".to_string(),
                        "Vui lòng kiểm tra và nhập chính xác mã 2FA gửi về iPhone/iPad!".to_string(),
                    ];
                    theme::error_box("ĐĂNG NHẬP CHƯA HOÀN TẤT", &err_lines);
                    return Err(anyhow!("Chưa nhận được AppToken"));
                }
                let token = token_opt.unwrap().clone();
                let mut lines = vec![
                    format!("Apple ID:  {}", theme::muted(&apple_id)),
                    format!("DSID:      {}", result.dsid.as_deref().unwrap_or("(none)")),
                ];
                let token_display = if token.len() > 30 {
                    format!("{}...", &token[..30])
                } else {
                    token.clone()
                };
                lines.push(format!("Token:     {}", token_display));
                theme::success_box("ĐĂNG NHẬP THÀNH CÔNG", &lines);

                // === LƯU SESSION ===
                if let Some(dsid) = result.dsid.clone() {
                    let mut session = Session {
                        apple_id: apple_id.clone(),
                        dsid: dsid.clone(),
                        session_token: result.session_token.clone().unwrap_or_default(),
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        team_id: None,
                        team_name: None,
                        created_at: fortiva::session::now(),
                        expires_at: fortiva::session::now() + 7 * 24 * 3600,
                        token_issued_at: fortiva::session::now(),   // ← MỚI
                    };

                    // === FETCH TEAM ID TU APPLE ===
                    if let Some(token) = result.session_token.clone() {
                        println!();
                        log::info("Dang lay Team ID tu Apple...");

                        if let Ok(mut dev) = fortiva::dev::DeveloperClient::new(
                            dsid.clone(),
                            token,
                        ) {
                            let mut ani = AnisetteClient::new(None);
                            match dev.list_teams(&mut ani) {
                                Ok(teams) if !teams.is_empty() => {
                                    let team = &teams[0];
                                    let tid = team
                                        .get("teamId")
                                        .or_else(|| team.get("teamID"))
                                        .and_then(|v| v.as_string())
                                        .map(|s| s.to_string());
                                    let tname = team
                                        .get("name")
                                        .and_then(|v| v.as_string())
                                        .map(|s| s.to_string());

                                    if let Some(id) = tid {
                                        log::success(&format!("Team ID: {}", id));
                                        if let Some(n) = &tname {
                                            log::info(&format!("Team name: {}", n));
                                        }
                                        session.team_id = Some(id);
                                        session.team_name = tname;
                                    }
                                }
                                Ok(_) => log::warn("Khong co team nao"),
                                Err(e) => log::warn(&format!("Khong lay duoc team: {}", e)),
                            }
                        }
                    }

                    match session.save() {
                        Ok(()) => {
                            log::success(&format!("✓ Đã lưu session cho {}", apple_id));
                            log::info("  Hết hạn sau: 7 ngày");
                        }
                        Err(e) => {
                            log::warn(&format!("⚠️  Không lưu được session: {}", e));
                        }
                    }

                    // Tự động kiểm tra và chuẩn bị Developer Certificate (kiểu iLoader)
                    if let (Some(token), Some(ref tid)) = (result.session_token.clone(), &session.team_id) {
                        println!();
                        log::info("Đang kiểm tra và chuẩn bị Developer Certificate...");
                        if let Ok(mut dev) = fortiva::dev::DeveloperClient::new(dsid.clone(), token) {
                            dev.set_team(tid.clone());
                            let mut ani = AnisetteClient::new(None);
                            match dev.ensure_certificate(&mut ani, "fortiva", &apple_id, tid) {
                                Ok(bundle) => {
                                    log::success(&format!("✓ Chứng chỉ sẵn sàng (ID: {})", bundle.certificate_id.as_deref().unwrap_or("OK")));
                                }
                                Err(e) => {
                                    log::warn(&format!("⚠️ Không tự động tải được cert: {:#}", e));
                                }
                            }
                        }
                    }
                } else {
                    log::warn("⚠️  Không có DSID — không lưu session");
                }
            } else {
                log::warn("Đăng nhập chưa hoàn tất.");
            }
        }
        Err(e) => {
            println!();
            log::error(&format!("SRP flow thất bại: {:#}", e));
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 2: TEST ANISETTE
// ============================================================

fn cmd_test_anisette() -> Result<()> {
    theme::clear_screen();
    log::header("CẤU HÌNH ANISETTE SERVER");

    println!("  {} Server hiện tại: {}\n", theme::primary("→"), fortiva::config::Config::anisette_url());
    let url = prompt_text("Nhập Anisette URL mới (Enter = kiểm tra server hiện tại):");
    let test_url = if url.is_empty() { None } else { Some(url.as_str()) };

    println!();
    let sp = spinner::new("Đang kiểm tra kết nối tới Anisette server...");
    let mut client = AnisetteClient::new(test_url);

    match client.fetch(true) {
        Ok(headers) => {
            sp.finish_and_clear();
            log::success(&format!("Nhận được {} headers thành công!", headers.len()));
            println!();

            let important = [
                "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                "X-Apple-I-MD-RINFO", "X-Mme-Device-Id",
                "X-Apple-I-Client-Time", "X-MMe-Client-Info",
            ];
            let mut lines = Vec::new();
            for key in &important {
                if let Some(v) = headers.get(*key) {
                    let display = if v.len() > 40 {
                        format!("{}...({} chars)", &v[..40], v.len())
                    } else {
                        v.clone()
                    };
                    lines.push(format!("{:<26} {}", theme::primary(key), display));
                }
            }
            theme::box_section("Anisette Headers", &lines);

            if !url.is_empty() && prompt_yn("Lưu URL này làm server mặc định? (y/n):") {
                fortiva::config::Config::set_anisette_url(&url)?;
                log::success("✓ Đã lưu Anisette URL vào config thành công!");
            }
        }
        Err(e) => {
            sp.finish_and_clear();
            log::error(&format!("Thất bại: {}", e));
            return Err(e);
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 3: TEST CSR
// ============================================================


// ============================================================
//  SIGN HELPERS
// ============================================================

#[allow(dead_code)]
struct SignInputs {
    ipa: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    profile: PathBuf,
}

#[allow(dead_code)]
fn collect_sign_inputs() -> Result<SignInputs> {
    let ipa_path = prompt_text("Đường dẫn IPA:");
    if ipa_path.is_empty() {
        return Err(anyhow!("Đường dẫn IPA không được rỗng"));
    }
    let ipa = PathBuf::from(shellexpand(&ipa_path));
    if !ipa.exists() {
        return Err(anyhow!("IPA không tồn tại: {}", ipa.display()));
    }

    let cert_path = prompt_text("Đường dẫn cert.pem:");
    let cert = PathBuf::from(shellexpand(&cert_path));
    if !cert.exists() {
        return Err(anyhow!("cert.pem không tồn tại: {}", cert.display()));
    }

    let key_path = prompt_text("Đường dẫn key.pem:");
    let key = PathBuf::from(shellexpand(&key_path));
    if !key.exists() {
        return Err(anyhow!("key.pem không tồn tại: {}", key.display()));
    }

    let profile_path = prompt_text("Đường dẫn profile.mobileprovision:");
    let profile = PathBuf::from(shellexpand(&profile_path));
    if !profile.exists() {
        return Err(anyhow!("profile.mobileprovision không tồn tại: {}", profile.display()));
    }

    Ok(SignInputs { ipa, cert, key, profile })
}

#[allow(dead_code)]
fn sign_with_progress(
    inputs: &SignInputs,
    label: &str,
) -> Result<(PathBuf, f64)> {
    use std::time::Instant;
    let start = Instant::now();

    let pb = progress::new_bar(100, label);

    let steps: &[(u64, &str)] = &[
        (10, "Đọc IPA"),
        (20, "Parse bundle tree"),
        (30, "Patch bundle ID"),
        (40, "Đăng ký App IDs"),
        (50, "Tạo App Group"),
        (60, "Inject special behavior"),
        (70, "Ghi Info.plist"),
        (80, "Nhúng profile"),
        (90, "Ký bundle tree"),
    ];

    pb.set_position(10);
    pb.set_message("Đọc IPA...");
    thread::sleep(Duration::from_millis(150));

    pb.set_position(20);
    pb.set_message("Khởi tạo sideloader...");

    let anisette = AnisetteClient::new(None);
    // Load session de dung token that
    let session = Session::load()?
        .ok_or_else(|| anyhow!("Chua login. Chay menu 1 truoc"))?;
    if session.is_expired() {
        return Err(anyhow!("Session het han. Login lai"));
    }
    let mut dev = fortiva::dev::DeveloperClient::new(
        session.dsid.clone(),
        session.session_token.clone(),
    )?;
    if let Some(tid) = &session.team_id {
        dev.set_team(tid.clone());
    }
    let work_dir = std::env::temp_dir().join("fortiva");
    std::fs::create_dir_all(&work_dir)?;

    let mut sideloader = fortiva::sideload::sideloader::Sideloader::new(dev, anisette, work_dir);

    pb.set_position(30);
    pb.set_message("Ký IPA (30s-2 phút)...");

    let signed_path = sideloader.sign_ipa(
        &inputs.ipa, &inputs.cert, &inputs.key, &inputs.profile,
    )?;

    // Animation nhanh cho các bước còn lại
    for (pos, msg) in &steps[3..] {
        if *pos <= 30 {
            continue;
        }
        pb.set_position(*pos);
        pb.set_message(*msg);
        thread::sleep(Duration::from_millis(80));
    }

    pb.set_position(100);
    pb.set_message("Hoàn tất");
    thread::sleep(Duration::from_millis(100));

    pb.finish_and_clear();
    let elapsed = start.elapsed().as_secs_f64();
    Ok((signed_path, elapsed))
}

// ============================================================
//  FEATURE 4: SIGN IPA
// ============================================================

#[allow(dead_code)]
fn cmd_sign_ipa() -> Result<()> {
    theme::clear_screen();
    log::header("SIGN IPA (CHỈ KÝ)");

    let inputs = collect_sign_inputs()?;

    println!();
    log::step(1, 1, "Ký IPA");

    let (signed_path, elapsed) = sign_with_progress(&inputs, "Đang ký IPA")?;

    let lines = vec![
        format!("Thời gian:  {:.1}s", elapsed),
        format!("App bundle: {}", signed_path.display()),
    ];
    theme::success_box("KÝ IPA THÀNH CÔNG", &lines);

    Ok(())
}

// ============================================================
//  FEATURE 5: SIGN + AUTO INSTALL
// ============================================================

#[allow(dead_code)]
fn cmd_sign_and_install() -> Result<()> {
    theme::clear_screen();
    log::header("SIGN + AUTO INSTALL");

    let status = get_iphone_status();
    println!("  📱 iPhone: {}", status);
    println!();

    if !prompt_yn("Tiếp tục? (y/n):") {
        return Ok(());
    }

    let inputs = collect_sign_inputs()?;

    // ===== BƯỚC 1: KÝ =====
    println!();
    log::step(1, 2, "Ký IPA");

    let (signed_path, sign_elapsed) = sign_with_progress(&inputs, "Đang ký IPA")?;
    log::success(&format!("Ký xong ({:.1}s)", sign_elapsed));

    // ===== BƯỚC 2: CÀI =====
    println!();
    log::step(2, 2, "Cài lên iPhone");

    let udid = match std::process::Command::new("idevice_id").arg("-l").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    };

    if udid.is_empty() {
        log::error("Không tìm thấy iPhone");
        log::info(&format!("IPA đã ký ở: {}", signed_path.display()));
        return Ok(());
    }

    log::info(&format!("UDID: {}", udid));

    let pb = progress::new_install_bar("Đang cài lên iPhone...");

    let install_result: Result<()> = (|| {
        for i in 0..=60 {
            pb.set_position(i as u64);
            if i == 10 { pb.set_message("Đang upload bundle..."); }
            if i == 40 { pb.set_message("Đang verify chữ ký..."); }
            thread::sleep(Duration::from_millis(20));
        }

        pb.set_message("Đang trigger install...");

        let rt = tokio::runtime::Runtime::new()
            .context("Không tạo được tokio runtime")?;

        let res = rt.block_on(async {
            fortiva::install::install_app_bundle(
    signed_path.to_string_lossy().as_ref(),
    &udid,
).await
        });

        for i in 61..=100 {
            pb.set_position(i as u64);
            if i == 90 { pb.set_message("Đang hoàn t..."); }
            thread::sleep(Duration::from_millis(15));
        }

        res.map_err(|e| anyhow!("{}", e))
    })();

    pb.finish_and_clear();

    match install_result {
        Ok(()) => {
            let lines = vec![
                format!("Thời gian:  {:.1}s", sign_elapsed + 1.5),
                format!("IPA:        {}", signed_path.display()),
            ];
            theme::success_box("🎉 KÝ + CÀI ĐẶT THÀNH CÔNG", &lines);
        }
        Err(e) => {
            log::warn(&format!("Cài đặt thất bại: {:#}", e));
            log::info("IPA đã ký:");
            println!("    {}", theme::muted(&signed_path.display().to_string()));
            println!();
            log::info("Cài thủ công bằng:");
            println!("    {} hoặc SideStore/AltStore",
                theme::muted("ideviceinstaller -i <ipa>"));
        }
    }

    Ok(())
}


// ============================================================
//  FEATURE 6: SETUP SIDESTORE PAIRING
// ============================================================

fn cmd_setup_sidestore_pairing() -> Result<()> {
    theme::clear_screen();
    log::header("SETUP SIDESTORE PAIRING");

    println!("  {} Tool ghi pairing file vào SideStore container", theme::muted("→"));
    println!("  {} để SideStore sideload không cần Mac.", theme::muted("→"));
    println!();
    println!("  {} Yêu cầu:", theme::muted("→"));
    println!("    {} iPhone đã cài SideStore", theme::muted("•"));
    println!("    {} Đã pair 1 lần (idevicepair pair)", theme::muted("•"));
    println!("    {} usbmuxd đang chạy", theme::muted("•"));
    println!();

    if !prompt_yn("Tiếp tục? (y/n):") {
        return Ok(());
    }

    let notify = |msg: &str| -> Result<bool> {
        println!();
        log::warn(msg);
        Ok(prompt_yn("Tiếp tục? (y/n):"))
    };

    let rt = tokio::runtime::Runtime::new()
        .context("Không tạo được tokio runtime")?;

    rt.block_on(async {
        fortiva::tools::setup_sidestore_pairing(notify).await
    })?;

    theme::success_box(
        "SETUP SIDESTORE THÀNH CÔNG",
        &["Mở SideStore → Settings để kiểm tra".to_string()],
    );

    Ok(())
}

// ============================================================
//  FEATURE 7: DEVICE MANAGER (LIST DEVICES)
// ============================================================

fn cmd_device_manager() -> Result<()> {
    theme::clear_screen();
    log::header("QUẢN LÝ THIẾT BỊ");

    // Khởi tạo clients giống pattern của sign_with_progress
    let mut auth = AnisetteClient::new(None);
    auth.fetch(false).context("Anisette fetch thất bại")?;

    let session = Session::load()?
        .ok_or_else(|| anyhow!("Chua login. Chay menu 1 truoc"))?;
    if session.is_expired() {
        return Err(anyhow!("Session het han. Login lai"));
    }
    let mut dev = fortiva::dev::DeveloperClient::new(
        session.dsid.clone(),
        session.session_token.clone(),
    )?;
    if let Some(tid) = &session.team_id {
        dev.set_team(tid.clone());
    }

    fortiva::tools::device_manager::list_devices(&mut dev, &mut auth)?;

    Ok(())
}

// ============================================================
//  FEATURE 8: REVOKE CERTIFICATES
// ============================================================

fn cmd_revoke_certs() -> Result<()> {
    theme::clear_screen();
    log::header("THU HỒI CHỨNG CHỈ");

    // Khởi tạo clients
    let mut auth = AnisetteClient::new(None);
    auth.fetch(false).context("Anisette fetch thất bại")?;

    let session = Session::load()?
        .ok_or_else(|| anyhow!("Chua login. Chay menu 1 truoc"))?;
    if session.is_expired() {
        return Err(anyhow!("Session het han. Login lai"));
    }
    let mut dev = fortiva::dev::DeveloperClient::new(
        session.dsid.clone(),
        session.session_token.clone(),
    )?;
    if let Some(tid) = &session.team_id {
        dev.set_team(tid.clone());
    }

    // 1. Liệt kê certs hiện có
    let certs = fortiva::tools::cert_manager::list_certs(&mut dev, &mut auth)?;

    if certs.is_empty() {
        return Ok(());
    }

    // 2. Hỏi user nhập STT cần revoke
    println!();
    let input = prompt_text("Nhập STT cert cần thu hồi (Enter = hủy):");

    if input.is_empty() {
        log::info("Đã hủy.");
        return Ok(());
    }

    // 3. Parse STT → validate range
    let idx: usize = match input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            log::error(&format!("STT không hợp lệ: {}", input));
            return Ok(());
        }
    };

    if idx < 1 || idx > certs.len() {
        log::error(&format!("STT ngoài phạm vi (1-{})", certs.len()));
        return Ok(());
    }

    let cert = &certs[idx - 1];
    let cert_id = cert
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Cert không có field id"))?
        .to_string();

    // 4. Xác nhận
    if !prompt_yn(&format!("Chắc chắn thu hồi cert {}? (y/n):", cert_id)) {
        log::info("Đã hủy.");
        return Ok(());
    }

    // 5. Revoke — truyền cert ID thật
    fortiva::tools::cert_manager::revoke_cert(&mut dev, &mut auth, &cert_id)?;

    Ok(())
}

// ============================================================
//  FEATURE 9: DEVICE INFO
// ============================================================

fn cmd_device_info() -> Result<()> {
    theme::clear_screen();
    log::header("THÔNG TIN THIẾT BỊ");

    let devices = fortiva::usb::list_usb_devices()?;

    if devices.is_empty() {
        log::warn("Không tìm thấy iPhone nào.");
        return Ok(());
    }

    println!("  {} {} thiết bị kết nối:\n", theme::primary("→"), devices.len());

    for (i, d) in devices.iter().enumerate() {
        match fortiva::usb::device_info(&d.udid) {
            Ok(info) => {
                let lines = vec![
                    format!("Tên:   {}", info.name),
                    format!("UDID:  {}", info.udid),
                    format!("Model: {}", info.model),
                    format!("iOS:   {}", info.version),
                ];
                theme::box_section(&format!("Device {}", i + 1), &lines);
            }
            Err(e) => {
                log::error(&format!("Không đọc được info: {}", e));
            }
        }
        println!();
    }

    Ok(())
}

// ============================================================
//  MAIN
// ============================================================



// ============================================================
//  AUTO REFRESH SESSION (sau 3 phut)
// ============================================================


// ============================================================
//  FEATURE 10: LOGOUT
// ============================================================

fn cmd_logout() -> Result<()> {
    theme::clear_screen();
    log::header("ĐĂNG XUẤT");

    let session = Session::load()?;
    let has_certs = dirs_home_certs_exists();

    match session {
        Some(s) => {
            println!("  {} Session hiện tại:", theme::primary("»"));
            println!("     Apple ID: {}", theme::muted(&s.apple_id));
            println!("     Team ID:  {}", theme::muted(s.team_id.as_deref().unwrap_or("?")));
            println!("     DSID:     {}", theme::muted(&s.dsid));
            println!();

            println!("  {} Sẽ xóa:", theme::warning("⚠"));
            println!("     - ~/.fortiva/session.json");
            if has_certs {
                println!("     - ~/.fortiva/certs/  (cert + private key)");
            }
            println!();

            if !prompt_yn("Xóa sạch dữ liệu account này? (y/n):") {
                log::info("Đã hủy.");
                return Ok(());
            }

            // 1. Xóa session
            Session::clear()?;
            log::success("✓ Đã xóa session");

            // 2. Xóa certs
            if has_certs {
                let home = std::env::var("HOME").unwrap_or_default();
                let certs_dir = std::path::PathBuf::from(home).join(".fortiva").join("certs");
                if let Err(e) = std::fs::remove_dir_all(&certs_dir) {
                    log::error(&format!("Xóa certs fail: {}", e));
                } else {
                    let _ = std::fs::create_dir_all(&certs_dir);
                    log::success("✓ Đã xóa certs/");
                }
            }

            println!();
            log::success("✓ Đã đăng xuất + dọn sạch dữ liệu account cũ");
            println!("  {} Chạy menu 1 để login account mới.", theme::muted("»"));
        }
        None => {
            log::info("Chưa có session nào.");
            // Vẫn cho xóa certs nếu có
            if has_certs {
                if prompt_yn("Không có session, nhưng có cert. Xóa certs? (y/n):") {
                    let home = std::env::var("HOME").unwrap_or_default();
                    let certs_dir = std::path::PathBuf::from(home).join(".fortiva").join("certs");
                    let _ = std::fs::remove_dir_all(&certs_dir);
                    let _ = std::fs::create_dir_all(&certs_dir);
                    log::success("✓ Đã xóa certs/");
                }
            }
        }
    }

    Ok(())
}

/// Check ~/.fortiva/certs/ có file gì không (không phải folder rỗng).
fn dirs_home_certs_exists() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return false,
    };
    let certs_dir = std::path::PathBuf::from(home).join(".fortiva").join("certs");
    if !certs_dir.exists() {
        return false;
    }
    match std::fs::read_dir(&certs_dir) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

// ============================================================
//  MAIN
// ============================================================


// ============================================================
//  FEATURE: SIDELOAD (CYDIA IMPACTOR MODE)
// ============================================================


// ============================================================
//  FEATURE: SIGN + INSTALL (ILOADER MODE)
// ============================================================

fn cmd_sign_auto() -> Result<()> {
    theme::clear_screen();
    log::header("SIGN IPA - ILOADER MODE");

    // Check session
    let session = ensure_session()?;

    println!("  Account: {}", theme::muted(&session.apple_id));
    if let Some(tid) = &session.team_id {
        println!("  Team:    {}", theme::muted(tid));
    }
    println!();

    let ipa = prompt_text("IPA path:");
    if ipa.is_empty() {
        return Err(anyhow!("IPA path rong"));
    }
    let ipa_path = PathBuf::from(shellexpand(&ipa));
    if !ipa_path.exists() {
        return Err(anyhow!("IPA khong ton tai: {}", ipa_path.display()));
    }

    let signed = match fortiva::sideload::auto::sign_ipa_auto(&ipa_path, &session) {
        Ok(path) => path,
        Err(e) if fortiva::auth::error::is_session_expired_error(&e) => {
            println!();
            log::warn("Session Apple ID đã hết hạn.");
            let _ = fortiva::session::Session::clear();
            if prompt_yn("Đăng nhập lại Apple ID ngay bây giờ? (y/n):") {
                cmd_login_apple_id()?;
                if let Ok(Some(new_session)) = fortiva::session::Session::load() {
                    fortiva::sideload::auto::sign_ipa_auto(&ipa_path, &new_session)?
                } else {
                    return Err(anyhow!("Đăng nhập lại chưa hoàn tất"));
                }
            } else {
                return Ok(());
            }
        }
        Err(e) => return Err(e),
    };

    println!();
    log::success(&format!("Signed: {}", signed.display()));

    if prompt_yn("Install len iPhone? (y/n):") {
        println!();
        log::info("Dang cai len iPhone...");
        let udid = fortiva::usb::first_udid()?;
        // install_app_bundle la async — can block_on
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("Tokio runtime fail: {}", e))?;
        rt.block_on(async {
            fortiva::install::install_app_bundle(
                signed.to_str().unwrap_or(""),
                &udid,
            ).await
        })?;
        log::success("Da cai thanh cong!");
    }

    Ok(())
}

fn main() {
    theme::clear_screen();

    menu::print_logo();
    let iphone = get_iphone_status();
    let account = get_account_status();
    menu::print_status_with_account(&iphone, &account);

    loop {
        let choice = prompt_choice();

        let result = match choice.as_str() {
            "1" => cmd_sign_auto(),
            "2" => cmd_login_apple_id(),
            "3" => cmd_test_anisette(),
            "4" => cmd_setup_sidestore_pairing(),
            "5" => cmd_device_manager(),
            "6" => cmd_revoke_certs(),
            "7" => cmd_device_info(),
            "8" | "logout" => cmd_logout(),
            "0" | "" => {
                theme::clear_screen();
                println!();
                log::info("Tạm biệt! 👋");
                return;
            }
            _ => {
                println!();
                log::warn(&format!("Lựa chọn không hợp lệ: {}", choice));
                pause();
                redraw_home();
                continue;
            }
        };

        if let Err(e) = result {
            println!();
            log::error(&format!("{:#}", e));
        }

        pause();
        redraw_home();
    }
}
