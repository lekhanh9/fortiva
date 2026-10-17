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
const LIVECONTAINER_PREFIX: &str = "com.kdt.livecontainer";
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
    println!("[pairing] === Setup Pairing File (SideStore & LiveContainer) ===\n");

    // 1. Kết nối usbmuxd
    println!("[pairing] Kết nối usbmuxd...");
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
    println!("[pairing] Device: {}", device.udid);

    // 2. Lấy pairing record từ usbmuxd
    println!("[pairing] Lấy pairing record...");
    let mut pairing_file = usbmuxd
        .get_pair_record(&device.udid)
        .await
        .context("Lấy pairing record thất bại (chạy: idevicepair pair)")?;

    pairing_file.udid = Some(device.udid.clone());
    println!("[pairing] Pairing record OK");

    // 3. Kết nối lockdown + start session
    let addr = UsbmuxdAddr::from_env_var()
        .unwrap_or_else(|_| UsbmuxdAddr::default());
    let provider = device.to_provider(addr, "fortiva");

    println!("[pairing] Start lockdown session...");
    let mut lc = LockdownClient::connect(&provider)
        .await
        .context("Kết nối lockdown thất bại")?;

    lc.start_session(&pairing_file)
        .await
        .context("Start session thất bại")?;
    println!("[pairing] ✅ Lockdown session started");

    // 4. Enable WiFi Debugging
    println!("[pairing] Enable WiFi debugging...");
    lc.set_value(
        "EnableWifiDebugging",
        plist::Value::Boolean(true),
        Some("com.apple.mobile.wireless_lockdown"),
    )
    .await
    .context("Enable WiFi debugging thất bại")?;
    println!("[pairing] ✅ WiFi debugging enabled");

    // 5. Serialize pairing file
    let pairing_data = pairing_file
        .serialize()
        .context("Serialize pairing file thất bại")?;
    println!("[pairing] Pairing file: {} bytes", pairing_data.len());

    // 6. Tìm SideStore & LiveContainer bundles
    println!("\n[pairing] Tìm kiếm SideStore & LiveContainer trên thiết bị...");
    let mut instproxy = InstallationProxyClient::connect(&provider)
        .await
        .context("Kết nối InstallationProxy thất bại")?;

    let apps = instproxy
        .browse(None)
        .await
        .context("Browse apps thất bại")?;

    let mut target_bundles: Vec<String> = apps
        .iter()
        .filter_map(|app| app.as_dictionary())
        .filter_map(|d| {
            d.get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
        })
        .filter(|id| {
            let lower = id.to_lowercase();
            id.starts_with(SIDESTORE_PREFIX)
                || id.starts_with(LIVECONTAINER_PREFIX)
                || lower.contains("sidestore")
                || lower.contains("livecontainer")
                || lower.contains("stik.store")
                || lower.contains("altstore")
        })
        .collect();

    target_bundles.sort();
    target_bundles.dedup();

    if target_bundles.is_empty() {
        return Err(anyhow!("Không tìm thấy SideStore hoặc LiveContainer trên iPhone"));
    }

    println!("[pairing] ✅ Tìm thấy {} ứng dụng tương thích:", target_bundles.len());
    for b in &target_bundles {
        let tag = if b.to_lowercase().contains("livecontainer") {
            "[LiveContainer]"
        } else if b.to_lowercase().contains("sidestore") {
            "[SideStore]"
        } else {
            "[Sideload App]"
        };
        println!("  • {:<16} {}", tag, b);
    }

    // 7. Ghi pairing file vào từng bundle
    println!("\n[pairing] Bắt đầu ghi pairing file vào các containers...");
    let mut success = 0;
    let mut failed = Vec::new();

    for (i, bundle_id) in target_bundles.iter().enumerate() {
        println!(
            "\n[pairing] ({}/{}) {}",
            i + 1,
            target_bundles.len(),
            bundle_id
        );

        match write_pairing_to_bundle(&provider, bundle_id, &device.udid, &pairing_data).await {
            Ok(()) => {
                println!("[pairing]   ✅ Đã ghi thành công!");
                success += 1;
            }
            Err(e) => {
                println!("[pairing]   ❌ {}", e);
                failed.push(bundle_id.clone());
                if i + 1 < target_bundles.len() {
                    if !notify(&format!("Lỗi {}. Tiếp tục các ứng dụng khác?", bundle_id))? {
                        break;
                    }
                }
            }
        }
    }

    println!(
        "\n[pairing] Tổng kết thành công: {}/{}",
        success,
        target_bundles.len()
    );

    if success == 0 {
        return Err(anyhow!("Không ghi được bundle nào"));
    }

    println!("\n[pairing] ✅ Hoàn tất ghi pairing file cho SideStore & LiveContainer!");
    Ok(())
}

async fn write_pairing_to_bundle(
    provider: &impl IdeviceProvider,
    bundle_id: &str,
    udid: &str,
    data: &[u8],
) -> Result<()> {
    let ha = HouseArrestClient::connect(provider)
        .await
        .context("House Arrest connect thất bại")?;

    let mut afc: AfcClient = ha
        .vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer thất bại: {}", bundle_id))?;

    // Đảm bảo thư mục /Documents tồn tại
    let _ = afc.mk_dir("/Documents").await;

    // Ghi 1: /Documents/pairingFile.plist (chuẩn SideStore & LiveContainer)
    let remote_path1 = format!("/Documents/{}", PAIRING_FILE_NAME);
    let mut file1 = afc
        .open(&remote_path1, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Mở file để ghi thất bại: {}", remote_path1))?;

    file1.write_entire(data)
        .await
        .with_context(|| format!("Ghi file thất bại: {}", remote_path1))?;

    file1.close()
        .await
        .context("Đóng AFC file thất bại")?;

    println!("[pairing]   ✓ Ghi {} bytes vào {}", data.len(), remote_path1);

    // Ghi 2: /Documents/{UDID}.plist (chuẩn LiveContainer JIT & StikDebug)
    let remote_path2 = format!("/Documents/{}.plist", udid);
    if let Ok(mut file2) = afc.open(&remote_path2, AfcFopenMode::WrOnly).await {
        if file2.write_entire(data).await.is_ok() {
            let _ = file2.close().await;
            println!("[pairing]   ✓ Ghi {} bytes vào {}", data.len(), remote_path2);
        }
    }

    Ok(())
}
