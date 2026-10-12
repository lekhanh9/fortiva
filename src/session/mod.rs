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
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).context("Đọc session file thất bại")?;
        let session: Session = serde_json::from_str(&content).context("Parse session JSON thất bại")?;
        Ok(Some(session))
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

    /// Tuoi cua token tinh bang giay.
    pub fn token_age_sec(&self) -> u64 {
        let now = now();
        let issued = if self.token_issued_at > 0 {
            self.token_issued_at
        } else {
            self.created_at
        };
        now.saturating_sub(issued)
    }

    /// Tuoi token tinh bang phut.
    pub fn token_age_min(&self) -> u64 {
        self.token_age_sec() / 60
    }

    /// Can refresh khong (mac dinh > 3 phut = 180s).
    pub fn needs_refresh(&self) -> bool {
        self.token_age_sec() > 420 // tương đương vs 7phút nếu hết thì sẽ buộc user login vào
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
