// src/sideload/sideloader.rs
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::signer::sign_app;
use crate::auth::anisette::AnisetteClient;
use crate::dev::DeveloperClient;

pub struct Sideloader {
    pub dev: DeveloperClient,
    pub anisette: AnisetteClient,
    pub work_dir: PathBuf,
    pub increased_memory_limit: bool,
}

impl Sideloader {
    pub fn new(dev: DeveloperClient, anisette: AnisetteClient, work_dir: PathBuf) -> Self {
        Self {
            dev,
            anisette,
            work_dir,
            increased_memory_limit: true,
        }
    }

    pub fn sign_ipa(
        &mut self,
        ipa_path: &Path,
        cert_pem: &Path,
        key_pem: &Path,
        profile_path: &Path,
    ) -> Result<PathBuf> {
        println!("\n[sideload] === Bắt đầu sign ===");

        // ============================================================
        // BƯỚC 1: Load cert
        // ============================================================
        let cert = CertificateIdentity::from_files(cert_pem, key_pem)
            .context("Load cert identity thất bại")?;
        println!("[sideload] Cert serial: {}", cert.serial_number());
        println!("[sideload] Team ID: {}", cert.machine_id);

        // ============================================================
        // BƯỚC 2: Load profile
        // ============================================================
        let mut profile_data = fs::read(profile_path)
            .with_context(|| format!("Đọc profile thất bại: {}", profile_path.display()))?;

        // ============================================================
        // BƯỚC 3: Parse IPA
        // ============================================================
        println!("\n[sideload] Parse IPA...");
        let mut app = Application::new(ipa_path.to_path_buf())?;

        // ============================================================
        // BƯỚC 4: Detect special app
        // ============================================================
        let special = app.get_special_app();
        match &special {
            Some(s) => println!("[sideload] 🎯 Special app: {}", s),
            None => println!("[sideload] App thường (không có special behavior)"),
        }

        // ============================================================
        // BƯỚC 5: Patch bundle ID
        // ============================================================
        let main_bundle_id = app.main_bundle_id()?;
        let team_id = cert.machine_id.clone();
        let new_bundle_id = format!("{}.{}", main_bundle_id, team_id);
        let main_app_name = app.main_app_name()?;

        println!(
            "\n[sideload] Patch bundle ID: {} → {}",
            main_bundle_id, new_bundle_id
        );
        app.update_bundle_id(&main_bundle_id, &new_bundle_id)?;
        app.write_all_info()?;  // ⚠️ GHI DISK

        // ============================================================
        // BƯỚC 6: Register App IDs (chỉ khi special app)
        // ============================================================
        let mut main_app_id: Option<crate::dev::AppId> = None;
        let mut extension_app_ids: Vec<(String, crate::dev::AppId)> = Vec::new();
        let mut extension_profiles: Vec<(String, Vec<u8>)> = Vec::new();

        if special.is_some() {
            println!("\n[sideload] Đăng ký App IDs với Apple...");

            // Main app ID
            match self.dev.ensure_app_id(
                &mut self.anisette,
                &new_bundle_id,
                &main_app_name,
            ) {
                Ok(id) => {
                    println!("[sideload] Main App ID: {}", id.identifier);
                    main_app_id = Some(id);
                }
                Err(e) => {
                    println!("[sideload] ⚠️ Không register được main App ID: {}", e);
                    println!("[sideload] Tiếp tục ký (không register extension)...");
                }
            }

            // Extension App IDs (nếu register main OK)
            if main_app_id.is_some() {
                let ext_bundles: Vec<_> = app
                    .bundle
                    .app_extensions()
                    .iter()
                    .filter_map(|ext| {
                        let id = ext.bundle_identifier()?.to_string();
                        let name = ext.bundle_name().unwrap_or("Extension").to_string();
                        Some((id, name))
                    })
                    .collect();

                for (ext_id, ext_name) in ext_bundles {
                    println!("[sideload] Extension: {} ({})", ext_id, ext_name);
                    match self.dev.ensure_app_id(
                        &mut self.anisette,
                        &ext_id,
                        &ext_name,
                    ) {
                        Ok(id) => extension_app_ids.push((ext_id, id)),
                        Err(e) => {
                            println!("[sideload] ⚠️ Extension fail: {}", e);
                        }
                    }
                }

                // ⚠️ Profile download SAU khi App Group assign (xem bước 7.5)
            }
        }

        // ============================================================
        // BƯỚC 7: Tạo + assign App Group (chỉ special app)
        // ============================================================
        let mut group_identifier: Option<String> = None;

        if special.is_some() && main_app_id.is_some() {
            let grp_id = format!(
                "group.{}",
                if matches!(special, Some(SpecialApp::SideStoreLc)) {
                    format!("com.SideStore.SideStore.{}", team_id)
                } else {
                    new_bundle_id.clone()
                }
            );

            println!("\n[sideload] App Group: {}", grp_id);

            match self.dev.ensure_app_group(
                &mut self.anisette,
                &grp_id,
                &main_app_name,
            ) {
                Ok(group) => {
                    // Assign main App ID
                    if let Some(ref main_id) = main_app_id {
                        let _ = self.dev.assign_app_group(
                            &mut self.anisette,
                            main_id,
                            &group,
                        );
                    }

                    // Assign extension App IDs
                    for (_, ext_app_id) in &extension_app_ids {
                        let _ = self.dev.assign_app_group(
                            &mut self.anisette,
                            ext_app_id,
                            &group,
                        );
                    }

                    group_identifier = Some(grp_id);
                }
                Err(e) => {
                    println!("[sideload] ⚠️ Không tạo được App Group: {}", e);
                    group_identifier = Some(grp_id); // vẫn dùng cho Info.plist
                }
            }
        }

        // ============================================================
        // BƯỚC 7.5: RE-DOWNLOAD profile SAU khi App Group đã assign
        // ⚠️ Profile PHẢI download sau bước 7 để có App Group entitlement
        // ============================================================
        if special.is_some() && main_app_id.is_some() {
            println!("\n[sideload] ⏳ Chờ Apple update App Group...");
            std::thread::sleep(std::time::Duration::from_secs(3));

            // Re-download main profile
            if let Some(ref main_id) = main_app_id {
                println!("[sideload] 🔄 Re-download main profile...");
                match self.dev.download_team_provisioning_profile(
                    &mut self.anisette,
                    main_id,
                ) {
                    Ok(p) => {
                        println!(
                            "[sideload] ✅ Main profile mới: {} bytes",
                            p.encoded_profile.len()
                        );
                        profile_data = p.encoded_profile;
                    }
                    Err(e) => {
                        println!("[sideload] ⚠️ Re-download main fail: {}", e);
                    }
                }
            }

            // Re-download extension profiles
            extension_profiles.clear();
            println!("[sideload] 🔄 Re-download ext profiles...");
            for (ext_id, ext_app_id) in &extension_app_ids {
                match self.dev.download_team_provisioning_profile(
                    &mut self.anisette,
                    ext_app_id,
                ) {
                    Ok(profile) => {
                        println!(
                            "[sideload] ✅ Ext profile mới: {} ({} bytes)",
                            ext_id,
                            profile.encoded_profile.len()
                        );
                        extension_profiles
                            .push((ext_id.clone(), profile.encoded_profile));
                    }
                    Err(e) => {
                        println!("[sideload] ⚠️ Re-download ext fail: {}", e);
                    }
                }
            }
        }

        // ============================================================
        // BƯỚC 8: Tăng memory limit cho LiveContainer/SideStoreLc
        // ============================================================
        if self.increased_memory_limit
            && matches!(
                special,
                Some(SpecialApp::LiveContainer) | Some(SpecialApp::SideStoreLc)
            )
            && main_app_id.is_some()
        {
            println!("\n[sideload] Bật Increased Memory Limit...");

            if let Some(ref main_id) = main_app_id {
                if let Err(e) = self.dev.add_increased_memory_limit(
                    &mut self.anisette,
                    main_id,
                ) {
                    println!("[sideload] ⚠️ Main app: {}", e);
                }
            }

            for (_, ext_id) in &extension_app_ids {
                if let Err(e) = self.dev.add_increased_memory_limit(
                    &mut self.anisette,
                    ext_id,
                ) {
                    println!("[sideload] ⚠️ Extension {}: {}", ext_id.identifier, e);
                }
            }
        }

        // ============================================================
        // BƯỚC 9: Apply special app behavior (inject cert p12)
        // ============================================================
        let effective_group = group_identifier
            .clone()
            .unwrap_or_else(|| format!("group.{}", new_bundle_id));

        app.apply_special_app_behavior(&special, &effective_group, &cert)?;

        // ============================================================
        // BƯỚC 10: Ghi Info.plist
        // ============================================================
        println!("\n[sideload] Ghi Info.plist (main + extension + framework)...");
        app.write_all_info()?;

        // ============================================================
        // BƯỚC 11: Nhúng profile
        // ============================================================
        println!("[sideload] Nhúng provisioning profile...");

        // 1. Nhúng profile user cung cấp vào MAIN bundle
        app.write_profiles(&profile_data)?;

        // 2. Nhúng profile RIÊNG vào từng extension (đã tải từ Apple API)
        for (ext_id, ext_profile) in &extension_profiles {
            if let Err(e) = app.write_profile_for_extension(ext_id, ext_profile) {
                println!(
                    "[sideload] ⚠️ Nhúng profile ext fail ({}): {}",
                    ext_id, e
                );
            }
        }

        // ============================================================
        // BƯỚC 12: Ký (multi-profile: main + từng ext)
        // ============================================================
        println!("\n[sideload] === Bắt đầu ký ===");
        
        sign_app(
            &mut app,
            &cert,
            &profile_data,
            &extension_profiles,   // Vec<(String, Vec<u8>)> đã sẵn
            &special,
            group_identifier.as_deref(),
        )?;

        let signed_path = app.bundle.bundle_dir.clone();
        println!("\n[sideload] ✅ Ký xong: {}", signed_path.display());

        // Summary special app behavior
        if let Some(s) = &special {
            println!("\n[sideload] 📋 Special app behavior đã áp dụng cho {}:", s);
            match s {
                SpecialApp::LiveContainer => {
                    println!("  ✓ ALTAppGroups injected");
                    println!("  ✓ 128 keychain-access-groups injected");
                    println!("  ✓ Increased Memory Limit");
                    println!("  ✓ Bundle ID patched");
                }
                SpecialApp::SideStoreLc => {
                    println!("  ✓ ALTAppGroups injected");
                    println!("  ✓ 128 keychain-access-groups injected");
                    println!("  ✓ Increased Memory Limit");
                    println!("  ✓ Cert p12 injected vào SideStore.framework");
                    println!("  ✓ Bundle ID patched");
                }
                SpecialApp::SideStore | SpecialApp::AltStore => {
                    println!("  ✓ ALTAppGroups injected");
                    println!("  ✓ Cert p12 injected vào main bundle");
                    println!("  ✓ Bundle ID patched");
                }
                SpecialApp::StikStore => {
                    println!("  ✓ Cert p12 (Certificate.p12) injected");
                    println!("  ✓ MachineID key injected");
                    println!("  ✓ Bundle ID patched");
                }
            }
        }

        Ok(signed_path)
    }
}