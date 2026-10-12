// src/dev/max_certs.rs
use anyhow::{anyhow, Result};

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

/// Hanh vi khi dat max certs.
/// Free account: 3 certs.
/// Paid account: 100 certs (khong handle).
pub enum MaxCertsBehavior {
    /// Tu dong revoke cert cu nhat.
    AutoRevokeOldest,
    /// Fail neu dat max.
    Fail,
    /// Revoke tat ca roi tao moi.
    RevokeAll,
}

impl Default for MaxCertsBehavior {
    fn default() -> Self {
        Self::AutoRevokeOldest
    }
}

/// Xu ly khi so cert >= max (3 cho free).
pub fn handle_max_certs(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
    certs: &[serde_json::Value],
    behavior: &MaxCertsBehavior,
) -> Result<()> {
    const MAX_FREE: usize = 3;

    if certs.len() < MAX_FREE {
        return Ok(());
    }

    println!(
        "[max_certs] Dat max {} certs (co {})",
        MAX_FREE,
        certs.len()
    );

    match behavior {
        MaxCertsBehavior::Fail => {
            return Err(anyhow!(
                "Dat max certs ({}). Revoke 1 cert truoc.",
                MAX_FREE
            ));
        }
        MaxCertsBehavior::AutoRevokeOldest => {
            let oldest = certs.iter().min_by_key(|c| {
                c.get("attributes")
                    .and_then(|a| a.get("expirationDate"))
                    .and_then(|e| e.as_str())
                    .unwrap_or("9999-99-99")
            }).or_else(|| certs.first());

            if let Some(oldest_cert) = oldest {
                let id = oldest_cert
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Cert thieu id"))?;

                println!("[max_certs] Revoke cert cu nhat: {}", id);
                dev.revoke_certificate(auth, id)?;
                println!("[max_certs] Revoked OK");
            }
        }
        MaxCertsBehavior::RevokeAll => {
            for cert in certs {
                if let Some(id) = cert.get("id").and_then(|v| v.as_str()) {
                    println!("[max_certs] Revoke: {}", id);
                    let _ = dev.revoke_certificate(auth, id);
                }
            }
        }
    }

    Ok(())
}
