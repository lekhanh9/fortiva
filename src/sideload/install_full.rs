// src/sideload/install_full.rs
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::auth::anisette::AnisetteClient;
use crate::dev::max_certs::{handle_max_certs, MaxCertsBehavior};
use crate::dev::DeveloperClient;
use crate::session::Session;
use crate::sideload::application::{Application, SpecialApp};
use crate::sideload::cert_identity::CertificateIdentity;
use crate::sideload::repack::repack_ipa;
use crate::sideload::signer::sign_app;
use crate::usb;

pub type ProgressCallback = Option<Box<dyn Fn(f32, &str)>>;

/// FULL AUTO: IPA -> sign -> repack -> (optional) install.
pub fn install_app_full(
    ipa_path: &Path,
    session: &Session,
    install: bool,
    progress: ProgressCallback,
) -> Result<(PathBuf, Option<SpecialApp>)> {
    let report = |p: f32, msg: &str| {
        if let Some(cb) = &progress {
            cb(p, msg);
        }
        println!("[{:>3}%] {}", (p * 100.0) as u32, msg);
    };

    println!();
    println!("========================================");
    println!("  INSTALL APP FULL (iLoader mode)");
    println!("========================================");
    println!();

    // 1. Setup DeveloperClient
    report(0.02, "Setup DeveloperClient");
    let mut dev = DeveloperClient::new(
        session.dsid.clone(),
        session.session_token.clone(),
    )?;
    if let Some(tid) = &session.team_id {
        dev.set_team(tid.clone());
    }
    let mut anisette = AnisetteClient::new(None);
    let team_id = session
        .team_id
        .as_ref()
        .ok_or_else(|| anyhow!("Session thieu team_id"))?
        .clone();

    // 2. Parse IPA
    report(0.05, "Parse IPA");
    let mut app = Application::new(ipa_path.to_path_buf())?;
    let special = app.get_special_app();
    let original_id = app.main_bundle_id()?;
    let main_name = app.main_app_name()?;
    println!("     App: {}", main_name);
    println!("     Bundle: {}", original_id);
    if let Some(s) = &special {
        println!("     Special: {}", s);
    }

    // 3. Cert
    report(0.15, "Get certificate");
    let certs = dev.list_certificates(&mut anisette)?;
    println!("     Existing certs: {}", certs.len());

    handle_max_certs(
        &mut dev,
        &mut anisette,
        &certs,
        &MaxCertsBehavior::AutoRevokeOldest,
    )?;

    // Load session de lay apple_id + team_id
    let session = crate::session::Session::load()?
        .ok_or_else(|| anyhow::anyhow!("Chua login — can login truoc"))?;
    let apple_id = session.apple_id.clone();
    let team_id_sess = session.team_id.clone().unwrap_or_default();
    let cert_bundle = dev.ensure_certificate(
        &mut anisette, "fortiva", &apple_id, &team_id_sess
    )?;
    let cert = CertificateIdentity::from_bundle(&cert_bundle)?;
    println!("     Cert serial: {}", cert.serial_number());

    // 4. Patch bundle ID — append team
    report(0.25, "Patch bundle ID");
    let new_id = format!("{}.{}", original_id, team_id);
    app.update_bundle_id(&original_id, &new_id)?;
    println!("     New ID: {}", new_id);

    // ⚠️ GHI Info.plist xuong disk (KHONG CHI DOI TRONG RAM!)
    println!("     Ghi Info.plist (main + ext + framework)...");
    app.write_all_info()?;
    println!("     ✅ Info.plist OK");

    // 5. Register App IDs
    report(0.35, "Register App IDs");
    let main_app_id = dev.ensure_app_id(&mut anisette, &new_id, &main_name)?;
    println!("     Main: {}", main_app_id.identifier);

    let mut ext_app_ids = Vec::new();
    for ext in app.bundle.app_extensions() {
        if let Some(ext_id) = ext.bundle_identifier() {
            let ext_id_str = ext_id.to_string();
            let ext_name = ext.bundle_name().unwrap_or("Extension").to_string();
            match dev.ensure_app_id(&mut anisette, &ext_id_str, &ext_name) {
                Ok(id) => {
                    println!("     Ext: {}", ext_id_str);
                    ext_app_ids.push((ext_id_str, id));
                }
                Err(e) => println!("     WARN ext: {}", e),
            }
        }
    }

    // 6. Register device
    report(0.45, "Register device");
    let udid = usb::first_udid()?;
    dev.ensure_device_registered(&mut anisette, "iPhone", &udid)?;
    let udid_short = if udid.len() >= 8 { &udid[..8] } else { &udid };
    println!("     UDID: {}", udid_short);

    // 7. Apply special app behavior
    if special.is_some() {
        report(0.50, "Apply special behavior");
        let group_id = format!("group.{}", new_id);
        match app.apply_special_app_behavior(&special, &group_id, &cert) {
            Ok(()) => println!("     Applied!"),
            Err(e) => println!("     WARN: {}", e),
        }
    }

    // 8. Download profiles
    report(0.55, "Download profiles");
    let main_profile = dev.download_team_provisioning_profile(
        &mut anisette,
        &main_app_id,
    )?;
    println!(
        "     Main profile: {} bytes",
        main_profile.encoded_profile.len()
    );

    let mut ext_profiles = Vec::new();
    for (ext_id, ext_app_id) in &ext_app_ids {
        match dev.download_team_provisioning_profile(&mut anisette, ext_app_id) {
            Ok(p) => {
                println!("     Ext profile: {} bytes", p.encoded_profile.len());
                ext_profiles.push((ext_id.clone(), p));
            }
            Err(e) => println!("     WARN: {}", e),
        }
    }

    // 9. Inject profiles
    report(0.65, "Inject profiles");
    app.write_profiles(&main_profile.encoded_profile)?;
    for (ext_id, ext_profile) in &ext_profiles {
        app.write_profile_for_extension(ext_id, &ext_profile.encoded_profile)?;
    }

    // 10. Sign (multi-profile: main + từng ext)
    report(0.75, "Sign bundle tree");
    
    let ext_profiles_vec: Vec<(String, Vec<u8>)> = ext_profiles
        .iter()
        .map(|(id, p)| (id.clone(), p.encoded_profile.clone()))
        .collect();
    
    let app_group = if special.is_some() {
        Some(format!("group.{}", new_id))
    } else {
        None
    };

    sign_app(
        &mut app,
        &cert,
        &main_profile.encoded_profile,
        &ext_profiles_vec,
        &special,
        app_group.as_deref(),
    )?;

    // 11. Repack
    report(0.85, "Repack IPA");
    let signed_ipa = repack_ipa(&app.bundle.bundle_dir)?;

    // 12. Install (optional)
    if install {
        report(0.95, "Install to iPhone");
        
        // install_app_bundle la async — can block_on
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("Tokio runtime fail: {}", e))?;
        
        rt.block_on(async {
            crate::install::install_app_bundle(
                signed_ipa.to_str().unwrap_or(""),
                &udid,
            ).await
        })?;
        
        println!("     Installed!");
    }

    report(1.0, "DONE");

    println!();
    println!("SIGNED IPA: {}", signed_ipa.display());
    println!();

    Ok((signed_ipa, special))
}
