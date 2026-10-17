// src/config/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::session::Session;

pub mod profiles;
pub use profiles::{DeviceProfile, DEVICE_PROFILES, find_profile};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub anisette: AnisetteConfig,
    #[serde(default)]
    pub client_info: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnisetteConfig {
    pub server_url: String,
}

impl Default for AnisetteConfig {
    fn default() -> Self {
        Self {
            server_url: crate::constants::ANISETTE_URL.to_string(),
        }
    }
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(Session::dir()?.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            let default = Self::default();
            default.save()?;
            return Ok(default);
        }
        let content = fs::read_to_string(&path).context("Doc config.json fail")?;
        serde_json::from_str(&content).context("Parse config.json fail")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn anisette_url() -> String {
        Self::load()
            .map(|c| c.anisette.server_url)
            .unwrap_or_else(|_| crate::constants::ANISETTE_URL.to_string())
    }

    pub fn set_anisette_url(url: &str) -> Result<()> {
        let mut config = Self::load()?;
        config.anisette.server_url = url.to_string();
        config.save()
    }

    pub fn client_info() -> String {
        if let Ok(ci) = std::env::var("FORTIVA_CLIENT_INFO") {
            let trimmed = ci.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        Self::load()
            .ok()
            .and_then(|c| c.client_info)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| crate::constants::DEFAULT_CLIENT_INFO.to_string())
    }

    pub fn user_agent() -> String {
        if let Ok(ua) = std::env::var("FORTIVA_USER_AGENT") {
            let trimmed = ua.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Ok(conf) = Self::load() {
            if let Some(ua) = conf.user_agent.filter(|s| !s.trim().is_empty()) {
                return ua;
            }
        }
        let ci = Self::client_info();
        crate::constants::match_user_agent_for_client_info(&ci)
    }

    pub fn active_profile_name() -> String {
        if let Ok(conf) = Self::load() {
            if let Some(p) = conf.profile {
                return p;
            }
            if let Some(ci) = conf.client_info {
                return format!("Custom ({})", if ci.len() > 30 { &ci[..30] } else { &ci });
            }
        }
        "Windows iTunes 12.12 (Default)".to_string()
    }

    pub fn set_client_info(ci: Option<&str>, ua: Option<&str>, profile: Option<&str>) -> Result<()> {
        let mut config = Self::load()?;
        config.client_info = ci.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        config.user_agent = ua.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        config.profile = profile.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        config.save()
    }

    pub fn apply_profile(profile_key: &str) -> Result<bool> {
        if let Some(prof) = find_profile(profile_key) {
            Self::set_client_info(
                Some(prof.client_info),
                Some(prof.user_agent),
                Some(prof.name),
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn reset_client_info() -> Result<()> {
        let mut config = Self::load()?;
        config.client_info = None;
        config.user_agent = None;
        config.profile = None;
        config.save()
    }
}

