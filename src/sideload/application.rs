// src/sideload/application.rs
use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::path::PathBuf;
use zip::ZipArchive;

use super::bundle::Bundle;
use super::cert_identity::CertificateIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialApp {
    SideStore,
    SideStoreLc,
    LiveContainer,
    AltStore,
    StikStore,
}

impl std::fmt::Display for SpecialApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecialApp::SideStore => write!(f, "SideStore"),
            SpecialApp::SideStoreLc => write!(f, "SideStore+LiveContainer"),
            SpecialApp::LiveContainer => write!(f, "LiveContainer"),
            SpecialApp::AltStore => write!(f, "AltStore"),
            SpecialApp::StikStore => write!(f, "StikStore"),
        }
    }
}

pub struct Application {
    pub bundle: Bundle,
}

impl Application {
    pub fn new(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Err(anyhow!("Path khong ton tai: {}", path.display()));
        }

        let mut bundle_path = path.clone();

        if path.is_file() {
            let temp_dir = std::env::temp_dir();
            let temp_path = temp_dir.join(format!(
                "{}_extracted",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("app")
            ));

            if temp_path.exists() {
                fs::remove_dir_all(&temp_path).context("Xoa temp dir cu that bai")?;
            }
            fs::create_dir_all(&temp_path).context("Tao temp dir that bai")?;

            println!("[app] Extract IPA vao {}", temp_path.display());

            let file = File::open(&path).context("Mo IPA that bai")?;
            let mut archive = ZipArchive::new(file).context("Doc IPA archive that bai")?;

            extract_ipa_preserving_symlinks(&mut archive, &temp_path)?;

            let payload_dir = temp_path.join("Payload");
            if !payload_dir.is_dir() {
                return Err(anyhow!("IPA khong co Payload/"));
            }

            let mut app_dirs = Vec::new();
            for entry in fs::read_dir(&payload_dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() && p.extension().is_some_and(|e| e == "app") {
                    app_dirs.push(p);
                }
            }

            if app_dirs.len() != 1 {
                return Err(anyhow!("Payload/ phai co dung 1 .app, tim thay {}", app_dirs.len()));
            }

            bundle_path = app_dirs.into_iter().next().unwrap();
        }

        let bundle = Bundle::new(bundle_path)?;
        Ok(Application { bundle })
    }

    pub fn get_special_app(&self) -> Option<SpecialApp> {
        let bundle_id = self.bundle.bundle_identifier().unwrap_or("");

        // ⭐ Match by prefix (bundle ID có thể có team suffix .TEAM_ID)
        if bundle_id == "com.rileytestut.AltStore"
            || bundle_id.starts_with("com.rileytestut.AltStore.")
        {
            return Some(SpecialApp::AltStore);
        }
        if bundle_id == "com.SideStore.SideStore"
            || bundle_id.starts_with("com.SideStore.SideStore.")
        {
            return Some(SpecialApp::SideStore);
        }
        if bundle_id == "app.stik.store"
            || bundle_id.starts_with("app.stik.store.")
        {
            return Some(SpecialApp::StikStore);
        }
        if bundle_id == "com.kdt.livecontainer"
            || bundle_id.starts_with("com.kdt.livecontainer.")
        {
            return Some(SpecialApp::LiveContainer);
        }

        if self
            .bundle
            .frameworks()
            .iter()
            .any(|fw| fw.bundle_identifier() == Some("com.SideStore.SideStore"))
        {
            return Some(SpecialApp::SideStoreLc);
        }

        None
    }

    pub fn main_bundle_id(&self) -> Result<String> {
        self.bundle
            .bundle_identifier()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Khong doc duoc CFBundleIdentifier"))
    }

    pub fn main_app_name(&self) -> Result<String> {
        self.bundle
            .bundle_name()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Khong doc duoc CFBundleName"))
    }

    pub fn update_bundle_id(
        &mut self,
        main_bundle_id: &str,
        main_app_id_str: &str,
    ) -> Result<()> {
        for ext in self.bundle.app_extensions_mut().iter_mut() {
            if let Some(id) = ext.bundle_identifier().map(|s| s.to_string()) {
                if !id.starts_with(main_bundle_id) || id.len() <= main_bundle_id.len() {
                    return Err(anyhow!(
                        "Extension bundle id {} khong thuoc main app {}",
                        id, main_bundle_id
                    ));
                }

                let suffix = &id[main_bundle_id.len()..];
                ext.set_bundle_identifier(&format!("{}{}", main_app_id_str, suffix));
            }
        }

        self.bundle.set_bundle_identifier(main_app_id_str);
        Ok(())
    }

    pub fn write_all_info(&self) -> Result<()> {
        self.bundle.write_info()?;
        for ext in self.bundle.app_extensions() {
            ext.write_info()?;
        }
        for fw in self.bundle.frameworks() {
            fw.write_info()?;
        }
        Ok(())
    }

    /// Nhúng profile vào MAIN bundle only.
    /// Extension sẽ nhận profile riêng qua `write_profile_for_extension`.
    pub fn write_profiles(&self, profile_data: &[u8]) -> Result<()> {
        let main_path = self.bundle.bundle_dir.join("embedded.mobileprovision");
        fs::write(&main_path, profile_data)
            .with_context(|| format!("Ghi profile that bai: {}", main_path.display()))?;
        println!("[app] Nhúng profile vào main bundle");
        Ok(())
    }

    /// Nhúng profile riêng cho từng extension theo bundle id.
    pub fn write_profile_for_extension(
        &self,
        extension_bundle_id: &str,
        profile_data: &[u8],
    ) -> Result<()> {
        for ext in self.bundle.app_extensions() {
            if ext.bundle_identifier() == Some(extension_bundle_id) {
                let ext_path = ext.bundle_dir.join("embedded.mobileprovision");
                fs::write(&ext_path, profile_data).with_context(|| {
                    format!("Ghi ext profile that bai: {}", ext_path.display())
                })?;
                println!("[app] Nhúng profile vào ext: {}", extension_bundle_id);
                return Ok(());
            }
        }
        Err(anyhow!(
            "Không tìm thấy extension: {}",
            extension_bundle_id
        ))
    }

    pub fn apply_special_app_behavior(
        &mut self,
        special: &Option<SpecialApp>,
        group_identifier: &str,
        cert: &CertificateIdentity,
    ) -> Result<()> {
        let special = match special.as_ref() {
            Some(s) => s,
            None => return Ok(()),
        };

        if matches!(
            special,
            SpecialApp::SideStoreLc
                | SpecialApp::SideStore
                | SpecialApp::AltStore
                | SpecialApp::StikStore
        ) {
            if !matches!(special, SpecialApp::StikStore) {
                self.bundle.app_info.insert(
                    "ALTAppGroups".to_string(),
                    plist::Value::Array(vec![plist::Value::String(group_identifier.to_string())]),
                );
            }

            println!("[app] Inject cert cho {}", special);

            let (id_key, cert_file_name) = match special {
                SpecialApp::StikStore => ("MachineID", "Certificate.p12"),
                _ => ("ALTCertificateID", "ALTCertificate.p12"),
            };

            let target_dir = match special {
                SpecialApp::SideStoreLc => self
                    .bundle
                    .frameworks_mut()
                    .iter_mut()
                    .find(|fw| fw.bundle_identifier() == Some("com.SideStore.SideStore"))
                    .map(|fw| fw.bundle_dir.clone()),
                _ => Some(self.bundle.bundle_dir.clone()),
            };

            if let Some(dir) = target_dir {
                let info_path = dir.join("Info.plist");
                let data = fs::read(&info_path)?;
                let mut plist_data: plist::Dictionary = plist::from_bytes(&data)?;
                plist_data.insert(
                    id_key.to_string(),
                    plist::Value::String(cert.serial_number()),
                );
                let file = File::create(&info_path)?;
                let mut w = std::io::BufWriter::new(file);
                plist::to_writer_binary(&mut w, &plist_data)?;

                let p12_bytes = cert.as_p12(&cert.machine_id)?;
                let cert_path = dir.join(cert_file_name);
                fs::write(&cert_path, p12_bytes)?;
                println!("[app] Ghi cert p12 vao {}", cert_path.display());
            }
        }

        Ok(())
    }
}

fn extract_ipa_preserving_symlinks(
    archive: &mut ZipArchive<File>,
    dest: &std::path::Path,
) -> Result<()> {
    use std::io::copy;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        let out_path = dest.join(&name);
        if !out_path.starts_with(dest) {
            return Err(anyhow!("Zip-slip detected: {}", name));
        }

        let mode = entry.unix_mode().unwrap_or(0o644);
        let is_symlink = (mode & 0o170000) == 0o120000;

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if is_symlink {
            let mut target = String::new();
            std::io::Read::read_to_string(&mut entry, &mut target)?;
            let target = target.trim();

            if out_path.exists() || out_path.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&out_path);
            }

            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, &out_path)
                    .with_context(|| format!("Tao symlink that bai: {}", out_path.display()))?;
            }
            #[cfg(windows)]
            {
                let _ = std::os::windows::fs::symlink_file(target, &out_path);
            }
        } else {
            let mut out = File::create(&out_path)?;
            copy(&mut entry, &mut out)?;

            #[cfg(unix)]
            {
                fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777))?;
            }
        }
    }

    Ok(())
}
