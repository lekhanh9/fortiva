// src/sideload/auto.rs
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::auth::anisette::AnisetteClient;
use crate::auth::gsa::GsaClient;
use crate::auth::srp::SrpFlow;
use crate::auth::twofa::TwoFAHandler;
use crate::dev::DeveloperClient;
use crate::session::Session;
use crate::sideload::application::{Application, SpecialApp};
use crate::sideload::cert_identity::CertificateIdentity;
use crate::sideload::signer::sign_app;
use crate::usb;

/// Sign IPA full auto tu session co san (iLoader mode).
pub fn sign_ipa_auto(
    ipa_path: &Path,
    session: &Session,
) -> Result<PathBuf> {
    println!();
    println!("========================================");
    println!("  AUTO SIGN - iLoader Mode");
    println!("========================================");
    println!();

    // 1. Setup DeveloperClient
    let mut dev = DeveloperClient::new(
        session.dsid.clone(),
        session.session_token.clone(),
    )?;
    if let Some(tid) = &session.team_id {
        dev.set_team(tid.clone());
    }
    let mut anisette = AnisetteClient::new(None);

    // 2. Team ID
    let team_id = session.team_id.as_ref()
        .ok_or_else(|| anyhow!("Session thieu team_id"))?
        .clone();
    println!("[1/8] Team: {}", team_id);

    // 3. Ensure certificate
    let apple_id = session.apple_id.clone();
    let team_id_opt = session.team_id.clone().unwrap_or_default();
    let cert_bundle = dev.ensure_certificate(&mut anisette, "fortiva", &apple_id, &team_id_opt)?;
    let cert = CertificateIdentity::from_bundle(&cert_bundle)?;
    println!("[2/8] Cert: {}", cert.serial_number());

    // 4. Parse IPA
    let mut app = Application::new(ipa_path.to_path_buf())?;
    let original_id = app.main_bundle_id()?;
    println!("[3/8] Bundle ID goc: {}", original_id);

    // 5. Patch bundle ID — append team (bắt buộc cho free account)
    let new_id = format!("{}.{}", original_id, team_id);
    app.update_bundle_id(&original_id, &new_id)?;
    app.write_all_info()?;  // ⚠️ GHI XUỐNG DISK
    println!("[4/8] Bundle ID moi: {}", new_id);

    // 6. Register App IDs
    let main_name = app.main_app_name()?;
    let main_app_id = dev.ensure_app_id(&mut anisette, &new_id, &main_name)?;
    println!("[5/8] App ID: {}", main_app_id.identifier);

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
                Err(e) => println!("     WARN Ext fail: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // BƯỚC 5.5: App Group & Special behavior (chỉ special app)
    // ════════════════════════════════════════════════════════════
    let special = app.get_special_app();
    let mut app_group_str: Option<String> = None;
    if let Some(ref sp) = special {
        let app_group_value = match sp {
            SpecialApp::SideStore | SpecialApp::SideStoreLc => {
                Some(format!("group.{}", new_id))
            }
            SpecialApp::AltStore => Some(format!("group.{}", new_id)),
            SpecialApp::LiveContainer => Some(format!("group.{}", new_id)),
            _ => None,
        };

        if let Some(group_id) = app_group_value {
            println!("[5.5/8] App Group: {}", group_id);

            match dev.ensure_app_group(&mut anisette, &group_id, &main_name) {
                Ok(group) => {
                    println!("     App Group registered: {}", group.group_id);

                    // Enable App Group feature cho main + ext App IDs
                    println!("     Enable App Group feature...");
                    if let Err(e) = dev.enable_app_group_feature(&mut anisette, &main_app_id) {
                        println!("     Enable main feature fail: {}", e);
                    }
                    for (ext_id, ext_app_id) in &ext_app_ids {
                        if let Err(e) = dev.enable_app_group_feature(&mut anisette, ext_app_id) {
                            println!("     Enable ext feature fail ({}): {}", ext_id, e);
                        }
                    }

                    println!("     Cho Apple update (2s)...");
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    match dev.assign_app_group(&mut anisette, &main_app_id, &group) {
                        Ok(_) => println!("     Assigned to main"),
                        Err(e) => println!("     Assign main fail: {}", e),
                    }

                    for (ext_id, ext_app_id) in &ext_app_ids {
                        match dev.assign_app_group(&mut anisette, ext_app_id, &group) {
                            Ok(_) => println!("     Assigned to ext: {}", ext_id),
                            Err(e) => println!("     Assign ext fail ({}): {}", ext_id, e),
                        }
                    }

                    app_group_str = Some(group_id.clone());
                }
                Err(e) => println!("     App Group register fail: {}", e),
            }

            // Inject special behavior (ALTCertificate.p12, ALTCertificateID cho SideStore)
            if let Err(e) = app.apply_special_app_behavior(&special, &group_id, &cert) {
                println!("     Apply special app behavior fail: {}", e);
            }
        }
    }

    // 7. Register UDID
    let udid = usb::first_udid()?;
    dev.ensure_device_registered(&mut anisette, "iPhone", &udid)?;
    let udid_short = if udid.len() >= 8 { &udid[..8] } else { &udid };
    println!("[6/8] UDID: {}", udid_short);

    // 8. Download profiles (main + ext)
    let main_profile = dev.download_team_provisioning_profile(
        &mut anisette,
        &main_app_id,
    )?;
    println!("[7/8] Main profile: {} bytes", main_profile.encoded_profile.len());

    let mut ext_profiles = Vec::new();
    for (ext_id, ext_app_id) in &ext_app_ids {
        match dev.download_team_provisioning_profile(&mut anisette, ext_app_id) {
            Ok(p) => {
                println!("     Ext profile: {} bytes", p.encoded_profile.len());
                ext_profiles.push((ext_id.clone(), p));
            }
            Err(e) => println!("     WARN Ext profile fail: {}", e),
        }
    }

    // 9. Nhung profiles vao bundle
    app.write_profiles(&main_profile.encoded_profile)?;
    for (ext_id, ext_profile) in &ext_profiles {
        app.write_profile_for_extension(ext_id, &ext_profile.encoded_profile)?;
    }

    // 10. Sign bundle tree (multi-profile: main + từng ext)
    let ext_profiles_vec: Vec<(String, Vec<u8>)> = ext_profiles
        .iter()
        .map(|(id, p)| (id.clone(), p.encoded_profile.clone()))
        .collect();

    sign_app(
        &mut app,
        &cert,
        &main_profile.encoded_profile,
        &ext_profiles_vec,
        &special,
        app_group_str.as_deref(),
    )?;
    println!("[8/8] Sign OK");

    let signed_path = app.bundle.bundle_dir.clone();
    println!();
    println!("SIGNED: {}", signed_path.display());
    println!();

    Ok(signed_path)
}

/// Full auto: login + sign + install (Cydia Impactor mode).
pub fn sideload_full(
    ipa_path: &Path,
    apple_id: &str,
    password: &str,
) -> Result<PathBuf> {
    println!();
    println!("========================================");
    println!("  SIDELOAD - Cydia Impactor Mode");
    println!("========================================");
    println!();

    // 1. Login
    println!("[1/3] Login Apple ID...");
    let mut anisette = AnisetteClient::new(None);
    anisette.fetch(false)?;

    let user_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();

    let mut gsa = GsaClient::new(anisette, user_id.clone(), device_id.clone());
    let mut twofa = TwoFAHandler::new();
    let mut srp = SrpFlow::new();

    let result = srp.authenticate(&mut gsa, &mut twofa, apple_id, password, 0)?;
    if !result.authenticated {
        return Err(anyhow!("Login fail"));
    }

    // 2. Fetch team
    println!("[2/3] Fetch team...");
    let mut dev = DeveloperClient::new(
        result.dsid.clone().unwrap_or_default(),
        result.session_token.clone().unwrap_or_default(),
    )?;
    let mut ani2 = AnisetteClient::new(None);
    let teams = dev.list_teams(&mut ani2)?;
    let team_id = teams.first()
        .and_then(|t| t.get("teamId"))
        .and_then(|v| v.as_string())
        .ok_or_else(|| anyhow!("Khong co team"))?
        .to_string();
    let team_name = teams.first()
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // 3. Save session
    let session = Session {
        apple_id: apple_id.to_string(),
        dsid: result.dsid.clone().unwrap_or_default(),
        session_token: result.session_token.clone().unwrap_or_default(),
        user_id,
        device_id,
        team_id: Some(team_id.clone()),
        team_name,
        created_at: crate::session::now(),
        expires_at: crate::session::now() + 7 * 24 * 3600,
        token_issued_at: crate::session::now(),
    };
    session.save()?;
    println!("Login OK - Team: {}", team_id);

    // 4. Sign IPA auto
    println!("[3/3] Sign IPA...");
    let signed_path = sign_ipa_auto(ipa_path, &session)?;

    println!();
    println!("HOAN TAT! Signed: {}", signed_path.display());
    println!();

    Ok(signed_path)
}
