// src/usb/mod.rs
//
// Detect iPhone qua USB sử dụng libimobiledevice tools.

use anyhow::{anyhow, Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub udid: String,
    pub name: String,
}

pub fn is_valid_udid(udid: &str) -> bool {
    if udid.len() == 40 && udid.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if udid.len() == 25 && udid.as_bytes()[8] == b'-' {
        let (prefix, suffix) = udid.split_at(8);
        let suffix = &suffix[1..];
        if prefix.chars().all(|c| c.is_ascii_hexdigit())
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }
    false
}

pub fn list_usb_devices() -> Result<Vec<UsbDevice>> {
    let output = Command::new("idevice_id")
        .arg("-l")
        .output()
        .context("Chạy idevice_id thất bại. Cài: pkg install libimobiledevice")?;

    if !output.status.success() {
        return Err(anyhow!(
            "idevice_id exit code: {}",
            output.status.code().unwrap_or(-1)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let devices: Vec<UsbDevice> = stdout
        .lines()
        .filter_map(|line| {
            let udid = line.trim().to_string();
            if is_valid_udid(&udid) {
                Some(UsbDevice {
                    name: format!("iPhone-{}", &udid[..8.min(udid.len())]),
                    udid,
                })
            } else {
                None
            }
        })
        .collect();

    Ok(devices)
}

pub fn first_udid() -> Result<String> {
    let devices = list_usb_devices()?;
    devices
        .into_iter()
        .next()
        .map(|d| d.udid)
        .ok_or_else(|| anyhow!("Không có iPhone kết nối"))
}

pub fn detect_status() -> String {
    let usbmuxd_ok = Command::new("pgrep")
        .args(["-f", "usbmuxd"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !usbmuxd_ok {
        return "🔴 DISCONNECTED (usbmuxd chưa chạy)".to_string();
    }

    match list_usb_devices() {
        Ok(devices) if !devices.is_empty() => {
            let d = &devices[0];
            if d.udid.len() >= 8 {
                format!("🟢 CONNECTED (UDID: {}...)", &d.udid[..8])
            } else {
                "🟢 CONNECTED".to_string()
            }
        }
        _ => "🔴 DISCONNECTED".to_string(),
    }
}

pub fn device_info(udid: &str) -> Result<DeviceDetail> {
    let name = run_ideviceinfo(udid, "DeviceName").unwrap_or_else(|| "(unknown)".to_string());
    let version = run_ideviceinfo(udid, "ProductVersion").unwrap_or_else(|| "(unknown)".to_string());
    let model = run_ideviceinfo(udid, "ProductType").unwrap_or_else(|| "(unknown)".to_string());

    Ok(DeviceDetail {
        udid: udid.to_string(),
        name,
        version,
        model,
    })
}

fn run_ideviceinfo(udid: &str, key: &str) -> Option<String> {
    let output = Command::new("ideviceinfo")
        .args(["-u", udid, "-k", key])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

#[derive(Debug, Clone)]
pub struct DeviceDetail {
    pub udid: String,
    pub name: String,
    pub version: String,
    pub model: String,
}
