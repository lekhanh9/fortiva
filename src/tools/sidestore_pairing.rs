// src/tools/sidestore_pairing.rs
// Flow chuẩn: usbmuxd → lockdown session → enable WiFi → ghi vào SideStore

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;

use idevice::lockdown::LockdownClient;
use idevice::provider::IdeviceProvider;
use idevice::services::afc::{AfcClient, opcode::AfcFopenMode};
use idevice::services::house_arrest::HouseArrestClient;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::IdeviceService;

const SIDESTORE_PREFIX: &str = "com.SideStore.SideStore";
const PAIRING_FILE_NAME: &str = "pairingFile.plist";

pub fn list_pairing_records() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dirs = Vec::new();

    if let Ok(prefix) = std::env::var("PREFIX") {
        dirs.push(PathBuf::from(format!("{}/var/lib/lockdown", prefix)));
    }
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(format!("{}/.pymobiledevice3", home)));
        dirs.push(PathBuf::from(format!("{}/.usbmuxd", home)));
    }
    dirs.push(PathBuf::from(
        "/data/data/com.termux/files/usr/var/lib/lockdown",
    ));
    dirs.push(PathBuf::from("/var/lib/lockdown"));
    dirs.push(PathBuf::from("/var/db/lockdown"));

    for dir in dirs {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "plist") {
                    found.push(path);
                }
            }
        }
    }

    found
}

pub async fn setup_sidestore_pairing<F>(notify: F) -> Result<()>
where
    F: Fn(&str) -> Result<bool>,
{
    println!("[sidestore] === Setup pairing file ===\n");

    // 1. Kết nối usbmuxd
    println!("[sidestore] Kết nối usbmuxd...");
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Kết nối usbmuxd thất bại")?;

    let devices = usbmuxd
        .get_devices()
        .await
        .context("Lấy devices thất bại")?;

    if devices.is_empty() {
        return Err(anyhow!("Không có iPhone kết nối"));
    }

    let device = &devices[0];
    println!("[sidestore] Device: {}", device.udid);

    // 2. Lấy pairing record từ usbmuxd
    println!("[sidestore] Lấy pairing record...");
    let mut pairing_file = usbmuxd
        .get_pair_record(&device.udid)
        .await
        .context("Lấy pairing record thất bại (chạy: idevicepair pair)")?;

    pairing_file.udid = Some(device.udid.clone());
    println!("[sidestore] Pairing record OK");

    // 3. Kết nối lockdown + start session
    let addr = UsbmuxdAddr::from_env_var()
        .unwrap_or_else(|_| UsbmuxdAddr::default());
    let provider = device.to_provider(addr, "fortiva");

    println!("[sidestore] Start lockdown session...");
    let mut lc = LockdownClient::connect(&provider)
        .await
        .context("Kết nối lockdown thất bại")?;

    lc.start_session(&pairing_file)
        .await
        .context("Start session thất bại")?;
    println!("[sidestore] ✅ Lockdown session started");

    // 4. Enable WiFi Debugging
    println!("[sidestore] Enable WiFi debugging...");
    lc.set_value(
        "EnableWifiDebugging",
        plist::Value::Boolean(true),
        Some("com.apple.mobile.wireless_lockdown"),
    )
    .await
    .context("Enable WiFi debugging thất bại")?;
    println!("[sidestore] ✅ WiFi debugging enabled");

    // 5. Serialize pairing file
    let pairing_data = pairing_file
        .serialize()
        .context("Serialize pairing file thất bại")?;
    println!("[sidestore] Pairing file: {} bytes", pairing_data.len());

    // 6. Tìm SideStore bundle
    println!("\n[sidestore] Query app list...");
    let mut instproxy = InstallationProxyClient::connect(&provider)
        .await
        .context("Kết nối InstallationProxy thất bại")?;

    let apps = instproxy
        .browse(None)
        .await
        .context("Browse apps thất bại")?;

    let sidestore_bundles: Vec<String> = apps
        .iter()
        .filter_map(|app| app.as_dictionary())
        .filter_map(|d| {
            d.get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
        })
        .filter(|id| id.starts_with(SIDESTORE_PREFIX))
        .collect();

    if sidestore_bundles.is_empty() {
        return Err(anyhow!("Không tìm thấy SideStore trên iPhone"));
    }

    println!("[sidestore] ✅ {} bundle:", sidestore_bundles.len());
    for b in &sidestore_bundles {
        println!("  - {}", b);
    }

    // 7. Ghi pairing file vào từng bundle
    println!("\n[sidestore] Ghi pairing file...");
    let mut success = 0;
    let mut failed = Vec::new();

    for (i, bundle_id) in sidestore_bundles.iter().enumerate() {
        println!(
            "\n[sidestore] ({}/{}) {}",
            i + 1,
            sidestore_bundles.len(),
            bundle_id
        );

        match write_pairing_to_bundle(&provider, bundle_id, &pairing_data).await {
            Ok(()) => {
                println!("[sidestore]   ✅ OK");
                success += 1;
            }
            Err(e) => {
                println!("[sidestore]   ❌ {}", e);
                failed.push(bundle_id.clone());
                if i + 1 < sidestore_bundles.len() {
                    if !notify(&format!("Lỗi {}. Tiếp tục?", bundle_id))? {
                        break;
                    }
                }
            }
        }
    }

    println!(
        "\n[sidestore] Thành công: {}/{}",
        success,
        sidestore_bundles.len()
    );

    if success == 0 {
        return Err(anyhow!("Không ghi được bundle nào"));
    }

    println!("\n[sidestore] ✅ Hoàn tất!");
    Ok(())
}

async fn write_pairing_to_bundle(
    provider: &impl IdeviceProvider,
    bundle_id: &str,
    data: &[u8],
) -> Result<()> {
    let ha = HouseArrestClient::connect(provider)
        .await
        .context("House Arrest connect thất bại")?;

    let mut afc: AfcClient = ha
        .vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer thất bại: {}", bundle_id))?;

    let remote_path = format!("/Documents/{}", PAIRING_FILE_NAME);
    let mut file = afc
        .open(&remote_path, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Mở file để ghi thất bại: {}", remote_path))?;

    file.write_entire(data)
        .await
        .with_context(|| format!("Ghi file thất bại: {}", remote_path))?;

    file.close()
        .await
        .context("Đóng AFC file thất bại")?;

    println!("[sidestore]   Ghi {} bytes vào {}", data.len(), remote_path);
    Ok(())
}
