// src/config/profiles.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub client_info: &'static str,
    pub user_agent: &'static str,
    pub description: &'static str,
}

pub const DEVICE_PROFILES: &[DeviceProfile] = &[
    DeviceProfile {
        id: "windows",
        name: "Windows iTunes 12.12 (iLoader fix 503 / SideStore)",
        client_info: "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>",
        user_agent: "akd/1.0 CFNetwork/808.1.4",
        description: "Chuẩn Windows iTunes 12.12 vượt qua lỗi 503 GrandSlam",
    },
    DeviceProfile {
        id: "mac_standard",
        name: "SideStore Standard (MacBookPro13,2 / macOS 13.1)",
        client_info: "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        user_agent: "akd/1.0 CFNetwork/808.1.4",
        description: "SideStore / isideload chuẩn MacBook macOS 13.1",
    },
    DeviceProfile {
        id: "pixel7",
        name: "Pixel 7 (Android 14) [Bypass -80045]",
        client_info: "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        user_agent: "akd/1.0 CFNetwork/808.1.4",
        description: "Android 14 Pixel 7 Profile tránh lỗi -80045",
    },
    DeviceProfile {
        id: "sonoma",
        name: "MacBook Pro 16\" M1 Max (macOS 14.5 Sonoma)",
        client_info: "<MacBookPro18,1> <Mac OS X;14.5;23F79> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        user_agent: "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
        description: "macOS Sonoma 14.5 (Darwin 23.5.0, CFNetwork 1496)",
    },
    DeviceProfile {
        id: "ventura",
        name: "MacBook Pro 14\" M1 Pro (macOS 13.5 Ventura)",
        client_info: "<MacBookPro18,3> <Mac OS X;13.5;22G74> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        user_agent: "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
        description: "macOS Ventura 13.5 (Darwin 22.6.0, CFNetwork 1410)",
    },
    DeviceProfile {
        id: "ios17",
        name: "iPhone 15 Pro (iOS 17.6.1)",
        client_info: "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        user_agent: "akd/1.0 CFNetwork/1498.700.2 Darwin/23.6.0",
        description: "iOS 17.6.1 (Darwin 23.6.0, CFNetwork 1498)",
    },
];

pub fn find_profile(key: &str) -> Option<&'static DeviceProfile> {
    let k = key.trim().to_lowercase();
    match k.as_str() {
        "1" | "win" | "windows" | "itunes" | "iloader" | "503" => Some(&DEVICE_PROFILES[0]),
        "2" | "mac" | "sidestore" | "isideload" | "standard" => Some(&DEVICE_PROFILES[1]),
        "3" | "pixel" | "android" | "pixel7" => Some(&DEVICE_PROFILES[2]),
        "4" | "sonoma" | "macos14" => Some(&DEVICE_PROFILES[3]),
        "5" | "ventura" | "macos13" => Some(&DEVICE_PROFILES[4]),
        "6" | "ios" | "ios17" | "iphone" => Some(&DEVICE_PROFILES[5]),
        _ => DEVICE_PROFILES.iter().find(|p| p.id == k || p.name.to_lowercase().contains(&k)),
    }
}
