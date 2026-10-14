// src/session/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub apple_id: String,
    pub dsid: String,
    pub session_token: String,
    pub user_id: String,
    pub device_id: String,
    pub team_id: Option<String>,
    pub team_name: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub token_issued_at: u64,       // Thoi diem fetch token
}

impl Session {
    pub fn dir() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".fortiva");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn path() -> Result<PathBuf> {
        Ok(Self::dir()?.join("session.json"))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    pub fn load() -> Result<Option<Self>> {
        let path = Self::path()?;
        if path.exists() {
            let content = fs::read_to_string(&path).context("Đọc session file thất bại")?;
            if let Ok(session) = serde_json::from_str::<Session>(&content) {
                return Ok(Some(session));
            }
        }

        // Fallback: Check apple_session.json in current directory
        let probe_file = PathBuf::from("apple_session.json");
        if probe_file.exists() {
            if let Ok(content) = fs::read_to_string(&probe_file) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    let apple_id = val.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let dsid = val.get("dsid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let session_token = val.get("app_token")
                        .and_then(|v| v.as_str())
                        .or_else(|| val.get("idms_token").and_then(|v| v.as_str()))
                        .unwrap_or("")
                        .to_string();

                    if !apple_id.is_empty() && !dsid.is_empty() && !session_token.is_empty() {
                        let team_id = val.get("team_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let team_name = val.get("team_name").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let now_ts = now();
                        let sess = Session {
                            apple_id,
                            dsid,
                            session_token,
                            user_id: uuid::Uuid::new_v4().to_string().to_uppercase(),
                            device_id: uuid::Uuid::new_v4().to_string().to_uppercase(),
                            team_id,
                            team_name,
                            created_at: now_ts,
                            expires_at: now_ts + 7 * 24 * 3600,
                            token_issued_at: now_ts,
                        };
                        let _ = sess.save();
                        return Ok(Some(sess));
                    }
                }
            }
        }

        Ok(None)
    }

    pub fn clear() -> Result<()> {
        let path = Self::path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        let now = now();
        self.expires_at > 0 && now >= self.expires_at
    }

    /// Tuổi của token tính bằng giây.
    pub fn token_age_sec(&self) -> u64 {
        let now = now();
        let issued = if self.token_issued_at > 0 {
            self.token_issued_at
        } else {
            self.created_at
        };
        now.saturating_sub(issued)
    }

    /// Tuổi token tính bằng phút.
    pub fn token_age_min(&self) -> u64 {
        self.token_age_sec() / 60
    }

    /// Cần refresh không (chỉ khi session hết hạn 7 ngày, tránh đăng nhập lặp lại).
    pub fn needs_refresh(&self) -> bool {
        self.is_expired()
    }

    pub fn time_left_str(&self) -> String {
        let now = now();
        if self.expires_at <= now {
            return "hết hạn".to_string();
        }
        let secs = self.expires_at - now;
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        if days > 0 { format!("{}d {}h", days, hours) } else { format!("{}h", hours) }
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
