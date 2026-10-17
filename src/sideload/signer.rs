// src/sideload/signer.rs
// Sign flow dùng apple-codesign crate (Dadoum's fork).

use anyhow::{anyhow, Context, Result};

use apple_codesign::{SettingsScope, SigningSettings, UnifiedSigner};
use apple_codesign::cryptography::InMemoryPrivateKey;
use x509_certificate::CapturedX509Certificate;

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;

pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    ext_profiles: &[(String, Vec<u8>)],
    special: &Option<SpecialApp>,
    app_group: Option<&str>,
) -> Result<()> {
    println!("[sign] === sign_app (apple-codesign) ===");

    let bundle_dir = app.bundle.bundle_dir.clone();
    if !bundle_dir.exists() {
        return Err(anyhow!("Bundle dir không tồn tại: {}", bundle_dir.display()));
    }

    // Xóa SC_Info (FairPlay)
    let sc_info = bundle_dir.join("SC_Info");
    if sc_info.exists() {
        println!("[sign] Xóa SC_Info/");
        std::fs::remove_dir_all(&sc_info).ok();
    }

    // ─────────────────────────────────────────────
    // 1. Nhúng profile vào bundle TRƯỚC khi sign
    // ─────────────────────────────────────────────
    std::fs::write(
        bundle_dir.join("embedded.mobileprovision"),
        profile_data,
    ).context("Ghi main profile fail")?;
    println!("[sign] Main profile: {} bytes", profile_data.len());

    for ext in app.bundle.app_extensions() {
        let ext_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => continue,
        };
        let ext_profile = ext_profiles.iter()
            .find(|(id, _)| id == &ext_id)
            .map(|(_, p)| p.as_slice())
            .ok_or_else(|| anyhow!("Ext {} thiếu profile riêng", ext_id))?;

        std::fs::write(
            ext.bundle_dir.join("embedded.mobileprovision"),
            ext_profile,
        ).with_context(|| format!("Ghi ext profile fail: {}", ext_id))?;
        println!("[sign] Ext profile: {} ({} bytes)", ext_id, ext_profile.len());
    }

    // ─────────────────────────────────────────────
    // 2. Setup SigningSettings
    // ─────────────────────────────────────────────
    let mut settings = SigningSettings::default();

    // Load private key
    let private_key = load_private_key(&cert.key_pem)?;

    // Load signing certificate
    let signing_cert = load_certificate(&cert.cert_pem)?;

    settings.set_signing_key(&private_key, signing_cert);

    // Tự động chain WWDR G3 + Root CA
    settings.chain_apple_certificates();
    println!("[sign] Cert chain tự động (WWDR G3 + Root)");

    // Set team ID từ certificate
    let team_id = settings
        .set_team_id_from_signing_certificate()
        .map(|s| s.to_string())
        .unwrap_or_default();
    if !team_id.is_empty() {
        println!("[sign] Team ID: {}", team_id);
    }

    // ─────────────────────────────────────────────
    // 3. Entitlements cho MAIN + EXTENSIONS
    // ─────────────────────────────────────────────
    let main_bundle_id = app.bundle.bundle_identifier().unwrap_or("").to_string();
    let main_ent_xml = extract_entitlements_xml_string(
        profile_data,
        app_group,
        special,
        &team_id,
        &main_bundle_id,
    )?;
    settings.set_entitlements_xml(SettingsScope::Main, main_ent_xml)?;
    println!("[sign] Main entitlements set");

    for ext in app.bundle.app_extensions() {
        let ext_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => continue,
        };
        let ext_profile = ext_profiles.iter()
            .find(|(id, _)| id == &ext_id)
            .map(|(_, p)| p.as_slice());
        if let Some(ext_prof) = ext_profile {
            let ext_ent_xml = extract_entitlements_xml_string(
                ext_prof,
                app_group,
                &None,
                &team_id,
                &ext_id,
            )?;
            let rel_path = ext.bundle_dir
                .strip_prefix(&bundle_dir)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| ext_id.clone());

            settings.set_entitlements_xml(
                SettingsScope::Path(rel_path.clone()),
                ext_ent_xml,
            )?;
            println!("[sign] Ext entitlements: {}", rel_path);
        }
    }

    // ─────────────────────────────────────────────
    // 4. Sign toàn bộ bundle (tự động bottom-up)
    // ─────────────────────────────────────────────
    println!("[sign] Bắt đầu sign bundle...");
    let signer = UnifiedSigner::new(settings);
    signer.sign_path_in_place(&bundle_dir)
        .context("UnifiedSigner fail")?;

    println!("[sign] ✅ DONE");
    Ok(())
}

/// Load private key PEM → impl KeyInfoSigner.
fn load_private_key(pem: &str) -> Result<InMemoryPrivateKey> {
    // Decode PEM → DER
    let pem_data = pem::parse(pem.as_bytes())
        .context("Parse PEM envelope fail")?;
    let der = pem_data.contents();

    // Thử PKCS#8 trước (phổ biến), fallback PKCS#1
    if let Ok(key) = InMemoryPrivateKey::from_pkcs8_der(der) {
        return Ok(key);
    }
    InMemoryPrivateKey::from_pkcs1_der(der)
        .context("Parse private key DER fail (thử PKCS8/PKCS1)")
}

/// Load certificate PEM → CapturedX509Certificate.
fn load_certificate(pem: &str) -> Result<CapturedX509Certificate> {
    CapturedX509Certificate::from_pem(pem)
        .context("Parse cert PEM fail")
}

/// Extract entitlements XML từ profile.
pub fn extract_entitlements_xml_string(
    profile_data: &[u8],
    app_group: Option<&str>,
    special: &Option<SpecialApp>,
    team_id: &str,
    bundle_id: &str,
) -> Result<String> {
    use plist::Value;

    let start = find_subsequence(profile_data, b"<plist");
    let end = rfind_subsequence(profile_data, b"</plist>");

    let (start, end) = match (start, end) {
        (Some(s), Some(e)) => (s, e + b"</plist>".len()),
        _ => return Err(anyhow!("Không tìm thấy <plist> trong profile")),
    };

    let plist: Value = plist::from_bytes(&profile_data[start..end])
        .context("Parse profile plist fail")?;

    let mut entitlements = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Profile plist không phải dict"))?
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("Profile thiếu Entitlements"))?
        .clone();

    if let Some(group) = app_group {
        let key = "com.apple.security.application-groups";
        let is_array = matches!(entitlements.get(key), Some(Value::Array(_)));
        if !is_array {
            entitlements.insert(key.to_string(), Value::Array(Vec::new()));
        }
        if let Some(Value::Array(arr)) = entitlements.get_mut(key) {
            let val = Value::String(group.to_string());
            if !arr.contains(&val) {
                arr.push(val);
                println!("[sign] Injected App Group: {}", group);
            }
        }
    }

    // Special case: LiveContainer / SideStoreLc cần 128 keychain groups
    let is_livecontainer = matches!(
        special,
        Some(SpecialApp::SideStoreLc) | Some(SpecialApp::LiveContainer)
    ) || bundle_id.to_lowercase().contains("livecontainer");

    if is_livecontainer && !team_id.is_empty() {
        println!("[sign] 🔑 Thêm 128 Keychain Access Groups cho LiveContainer...");
        let mut keychain_groups = vec![
            Value::String(format!("{}.{}", team_id, bundle_id)),
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
        println!("[sign] ✅ Đã nhúng 128 keychain-access-groups vào signature entitlements");
    }

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(entitlements))
        .context("Serialize entitlements XML fail")?;

    String::from_utf8(buf).context("Entitlements XML không phải UTF-8")
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
