#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""device_profiles.py - Quản lý Client-Info và User-Agent đồng bộ cho Apple GSA / Developer API
Đảm bảo User-Agent luôn khớp chính xác 100% với phiên bản OS trong Client-Info,
tránh lỗi -80045 (lệch vân tay phần cứng) và lỗi 503 / 1200 trên Apple GrandSlam.
Bao gồm profile iLoader v2.3.8 fix 503 mới nhất!
"""

import re

PROFILES = {
    "1": {
        "id": "sidestore_standard",
        "name": "SideStore / isideload Standard (MacBookPro13,2 / macOS 13.1) 🔥 [Recommended]",
        "client_info": "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/808.1.4",
        "xcode_ua": "akd/1.0 CFNetwork/808.1.4",
        "anisette_url": "https://ani.sidestore.io",
        "description": "Standard SideStore / isideload profile, matches official Anisette servers",
    },
    "2": {
        "id": "windows_iloader",
        "name": "Windows iTunes 12.12 / AuthKit (iLoader v2.3.8 fix 503)",
        "client_info": "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>",
        "user_agent": "akd/1.0 CFNetwork/808.1.4",
        "xcode_ua": "akd/1.0 CFNetwork/808.1.4",
        "anisette_url": "http://127.0.0.1:6969",
        "description": "iLoader v2.3.8 / jkcoxson standard configuration (Windows 8 / iTunes 12.12 / AuthKit akd)",
    },
    "3": {
        "id": "android_pixel7",
        "name": "Pixel 7 (Android 14) [Bypass -80045]",
        "client_info": "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/808.1.4",
        "xcode_ua": "akd/1.0 CFNetwork/808.1.4",
        "anisette_url": "https://ani.sidestore.io",
        "description": "Android 14 Pixel 7 Profile",
    },
    "4": {
        "id": "macos_sonoma",
        "name": "MacBook Pro 16\" M1 Max (macOS 14.5 Sonoma)",
        "client_info": "<MacBookPro18,1> <Mac OS X;14.5;23F79> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
        "xcode_ua": "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
        "anisette_url": "https://ani.sidestore.io",
        "description": "macOS Sonoma 14.5 (Darwin 23.5.0, CFNetwork 1496)",
    },
    "5": {
        "id": "macos_ventura",
        "name": "MacBook Pro 14\" M1 Pro (macOS 13.5 Ventura)",
        "client_info": "<MacBookPro18,3> <Mac OS X;13.5;22G74> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
        "xcode_ua": "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
        "anisette_url": "https://ani.sidestore.io",
        "description": "macOS Ventura 13.5 (Darwin 22.6.0, CFNetwork 1410)",
    },
    "6": {
        "id": "ios_17",
        "name": "iPhone 15 Pro (iOS 17.6.1)",
        "client_info": "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/1498.700.2 Darwin/23.6.0",
        "xcode_ua": "akd/1.0 CFNetwork/1498.700.2 Darwin/23.6.0",
        "anisette_url": "https://ani.sidestore.io",
        "description": "iOS 17.6.1 (Darwin 23.6.0, CFNetwork 1498)",
    },
    "7": {
        "id": "auto_anisette",
        "name": "Auto (Retrieve from Anisette & auto-match User-Agent)",
        "client_info": None,
        "user_agent": None,
        "xcode_ua": None,
        "anisette_url": "https://ani.sidestore.io",
        "description": "Fetch Client-Info from Anisette server and automatically match User-Agent",
    },
}


def sanitize_client_info(raw_ci):
    """Làm sạch Client-Info: đổi com.apple.dt.Xcode thành com.apple.akd."""
    if not raw_ci:
        return PROFILES["1"]["client_info"]
    ci = re.sub(r"\(com\.apple\.dt\.Xcode[^)]*\)", "(com.apple.akd/1.0)", raw_ci)
    if "com.apple.dt.Xcode" in ci:
        ci = ci.replace("com.apple.dt.Xcode", "com.apple.akd")
    return ci


def match_user_agent_for_client_info(client_info):
    """Tự động suy ra User-Agent chuẩn và khớp 100% với chuỗi Client-Info."""
    if not client_info:
        return "iTunes/12.12.4 (Windows; Microsoft Windows 10 x64; x64) AppleWebKit/7613.2007"

    ci_lower = client_info.lower()

    if "windows" in ci_lower or "itunes" in ci_lower:
        return "akd/1.0 CFNetwork/808.1.4"
    if "android" in ci_lower:
        return "akd/1.0 CFNetwork/808.1.4"
    if "15." in client_info or "darwin/24" in ci_lower:
        return "akd/1.0 CFNetwork/1568.100.1 Darwin/24.0.0"
    if "14." in client_info or "darwin/23" in ci_lower:
        return "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0"
    if "13." in client_info or "darwin/22" in ci_lower:
        return "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0"
    if "12." in client_info or "darwin/21" in ci_lower:
        return "akd/1.0 CFNetwork/1335.0.3 Darwin/21.6.0"
    if "ios;18" in ci_lower:
        return "akd/1.0 CFNetwork/1568.100.1 Darwin/24.0.0"
    if "ios;17" in ci_lower:
        return "akd/1.0 CFNetwork/1498.700.2 Darwin/23.6.0"
    if "ios;16" in ci_lower:
        return "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"

    # Mặc định an toàn
    return "akd/1.0 CFNetwork/1410.0.3 Darwin/22.6.0"


def print_profile_menu():
    print("\n  ╭─────────────────────────────────────────────────────────────────╮")
    print("  │ 🛠️  SELECT DEVICE CONFIGURATION (CLIENT-INFO & MATCHING UA)      │")
    print("  ╰─────────────────────────────────────────────────────────────────╯")
    for key, p in PROFILES.items():
        tag = "⭐ RECOMMENDED" if key == "1" else ""
        print(f"    [{key}] {p['name']} {tag}")
    print("    [8] ✍️  Custom Client-Info & User-Agent manual entry")
    print()


def prompt_select_profile(default="1"):
    print_profile_menu()
    choice = input(f"  » Select profile (1-8, Enter for default [{default}]): ").strip()
    if not choice:
        choice = default

    if choice in PROFILES:
        p = PROFILES[choice]
        if choice == "7":
            return {"mode": "auto", "client_info": None, "user_agent": None, "xcode_ua": None, "anisette_url": p.get("anisette_url")}
        return {
            "mode": p["id"],
            "client_info": p["client_info"],
            "user_agent": p["user_agent"],
            "xcode_ua": p["xcode_ua"],
            "anisette_url": p.get("anisette_url"),
        }
    elif choice == "8":
        print("\n  --- MANUAL CONFIGURATION ---")
        ci = input("  » Enter Client-Info: ").strip()
        if not ci:
            ci = PROFILES["1"]["client_info"]
        ci = sanitize_client_info(ci)

        suggested_ua = match_user_agent_for_client_info(ci)
        print(f"  ℹ️  Suggested matching User-Agent: {suggested_ua}")
        ua = input(f"  » Enter User-Agent (Enter to accept suggested): ").strip()
        if not ua:
            ua = suggested_ua

        return {
            "mode": "custom",
            "client_info": ci,
            "user_agent": ua,
            "xcode_ua": ua,
            "anisette_url": None,
        }
    else:
        print(f"  ⚠️ Invalid choice, falling back to [1] SideStore Standard MacBook.")
        p = PROFILES["1"]
        return {
            "mode": p["id"],
            "client_info": p["client_info"],
            "user_agent": p["user_agent"],
            "xcode_ua": p["xcode_ua"],
            "anisette_url": p.get("anisette_url"),
        }
