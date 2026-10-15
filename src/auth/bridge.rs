use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::session::Session;

pub const APPLE_BRIDGE_PY: &str = include_str!("../../scripts/apple_bridge.py");
pub const APPLE_AUTH_PY: &str = include_str!("../../scripts/apple_auth.py");
pub const DEVELOPER_API_PY: &str = include_str!("../../scripts/developer_api.py");
pub const DEVICE_PROFILES_PY: &str = include_str!("../../scripts/device_profiles.py");

/// Kiểm tra python3 có sẵn trong hệ thống không.
pub fn is_python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Tìm hoặc bung các file bridge script Python ra thư mục hoạt động.
pub fn ensure_bridge_scripts() -> Result<PathBuf> {
    // 1. Kiểm tra trong ./scripts/apple_bridge.py
    let local_script = PathBuf::from("scripts/apple_bridge.py");
    if local_script.is_file() {
        return Ok(local_script);
    }

    // 2. Kiểm tra cạnh file thực thi fortiva
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let candidate = parent.join("scripts").join("apple_bridge.py");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 3. Tự động bung embedded scripts vào ~/.fortiva/scripts/
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let target_dir = PathBuf::from(home).join(".fortiva").join("scripts");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("Failed to create directory {:?}", target_dir))?;

    let bridge_py = target_dir.join("apple_bridge.py");
    let auth_py = target_dir.join("apple_auth.py");
    let dev_py = target_dir.join("developer_api.py");
    let profiles_py = target_dir.join("device_profiles.py");

    fs::write(&bridge_py, APPLE_BRIDGE_PY)?;
    fs::write(&auth_py, APPLE_AUTH_PY)?;
    fs::write(&dev_py, DEVELOPER_API_PY)?;
    fs::write(&profiles_py, DEVICE_PROFILES_PY)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bridge_py)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bridge_py, perms).ok();
    }

    Ok(bridge_py)
}

/// Run Apple Auth Python Bridge to authenticate and obtain Xcode AppToken.
pub fn run_python_login(
    apple_id: Option<&str>,
    password: Option<&str>,
) -> Result<Session> {
    if !is_python_available() {
        return Err(anyhow!(
            "Python 3 is not installed on this system! Please install python3 (e.g., apt install python3 or pkg install python)."
        ));
    }

    let script_path = ensure_bridge_scripts()
        .context("Failed to initialize Python bridge scripts")?;

    let mut cmd = Command::new("python3");
    cmd.arg(&script_path).arg("login");

    if let Some(id) = apple_id {
        if !id.is_empty() {
            cmd.arg("--apple-id").arg(id);
        }
    }
    if let Some(pwd) = password {
        if !pwd.is_empty() {
            cmd.arg("--password").arg(pwd);
        }
    }

    // Attach TTY/Terminal directly so 2FA prompts work interactively
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd.status().context("Failed to execute Python bridge subprocess")?;
    if !status.success() {
        return Err(anyhow!("Python bridge login failed."));
    }

    // Load session saved by Python bridge
    let session = Session::load()?
        .ok_or_else(|| anyhow!("Session file not found after login."))?;

    if session.is_expired() {
        return Err(anyhow!("Newly created session is invalid or expired."));
    }

    Ok(session)
}

/// Verify session validity with Apple Developer Services via Python Bridge.
pub fn run_python_test_session() -> Result<()> {
    if !is_python_available() {
        return Err(anyhow!("Python 3 not found on this system."));
    }

    let script_path = ensure_bridge_scripts()?;
    let status = Command::new("python3")
        .arg(&script_path)
        .arg("test-session")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        return Err(anyhow!("Test session failed."));
    }
    Ok(())
}
