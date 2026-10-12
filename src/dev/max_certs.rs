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
            let mut candidates: Vec<&serde_json::Value> = certs.iter().collect();
            candidates.sort_by_key(|c| {
                c.get("attributes")
                    .and_then(|a| a.get("expirationDate"))
                    .and_then(|e| e.as_str())
                    .and_then(super::certificate::parse_expiration_date)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(i64::MAX)
            });

            let mut revoked = false;
            for candidate in candidates {
                if let Some(id) = candidate.get("id").and_then(|v| v.as_str()) {
                    let exp_display = candidate
                        .get("attributes")
                        .and_then(|a| a.get("expirationDate"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("unknown");
                    println!("[max_certs] Thu hồi cert cũ nhất: {} (hạn: {})", id, exp_display);
                    if dev.revoke_certificate(auth, id)? {
                        println!("[max_certs] ✅ Thu hồi thành công cert: {}", id);
                        revoked = true;
                        break;
                    } else {
                        eprintln!("[max_certs] ⚠️ Không thu hồi được cert {}, thử cert tiếp theo...", id);
                    }
                }
            }

            if !revoked {
                return Err(anyhow!("Không thể thu hồi bất kỳ chứng chỉ nào trên Apple Developer"));
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
