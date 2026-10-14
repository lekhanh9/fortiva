#!/usr/bin/env python3
"""
=============================================================================
  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO & SERVICES PROBER TOOL
=============================================================================
Công cụ kiểm tra tự động các mẫu Client-Info và Services của Apple
trực tiếp lên máy chủ xác thực gsa.apple.com mà KHÔNG CẦN NHẬP MẬT KHẨU.
=============================================================================
"""

import urllib.request
import json
import plistlib
import ssl
import uuid
import base64
import random
import time
import sys

# SRP 2048 parameters (Apple GrandSlam standard)
N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
N = int(N_HEX, 16)
g = 2

ANISETTE_SERVERS = [
    "https://ani.sidestore.io",
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
    "http://localhost:6969",
]

def fetch_anisette():
    """Lấy Anisette headers từ các server dự phòng"""
    for server in ANISETTE_SERVERS:
        try:
            req = urllib.request.urlopen(server, timeout=8)
            data = json.loads(req.read().decode())
            if "X-Apple-I-MD-M" in data:
                return data, server
        except Exception:
            continue
    raise RuntimeError("Không thể kết nối đến bất kỳ Anisette server nào!")

def test_single_client_info(ci, ua, svct, ani):
    """Gửi init SRP request lên gsa.apple.com để kiểm tra phản hồi"""
    user_id = str(uuid.uuid4()).upper()
    device_id = ani.get("X-Mme-Device-Id", str(uuid.uuid4()).upper())
    
    # Sinh khoá công khai SRP ngẫu nhiên
    a = random.getrandbits(256)
    A_int = pow(g, a, N)
    A_bytes = A_int.to_bytes(256, byteorder="big")

    cpd = {
        "bootstrap": True,
        "icscrec": True,
        "pbe": False,
        "prkgen": True,
        "svct": svct,
        "loc": "en_US",
        "X-Apple-Locale": "en_US",
        "X-Apple-I-MD": ani.get("X-Apple-I-MD", ""),
        "X-Apple-I-MD-M": ani.get("X-Apple-I-MD-M", ""),
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-MD-LU": base64.b64encode(user_id.encode()).decode(),
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-SRL-NO": "0",
        "X-Apple-I-Client-Time": ani.get("X-Apple-I-Client-Time", ""),
        "X-Apple-I-TimeZone": "UTC",
        "X-MMe-Client-Info": ci,
    }

    req_dict = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "cpd": cpd,
            "o": "init",
            "u": f"probe_test_{user_id[:8].lower()}@icloud.com",
            "A2k": A_bytes,
            "ps": ["s2k", "s2k_fo"]
        }
    }

    body = plistlib.dumps(req_dict)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "User-Agent": ua,
        "X-Mme-Client-Info": ci,
        "X-Apple-I-MD": ani.get("X-Apple-I-MD", ""),
        "X-Apple-I-MD-M": ani.get("X-Apple-I-MD-M", ""),
        "X-Apple-I-MD-LU": base64.b64encode(user_id.encode()).decode(),
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-Client-Time": ani.get("X-Apple-I-Client-Time", ""),
        "X-Apple-I-SRL-NO": "0",
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": "en_US",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request("https://gsa.apple.com/grandslam/GsService2", data=body, headers=headers)
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        parsed = plistlib.loads(resp.read())
        resp_dict = parsed.get("Response", {})
        status = resp_dict.get("Status", {})
        ec = status.get("ec", 0)
        em = status.get("em", "")

        # ec = -80045: Apple chặn thẳng Client-Info
        if ec == -80045:
            return False, ec, em
        # ec = -20101: Apple chấp nhận Client-Info & thiết bị, chỉ báo account rỗng/sai
        return True, ec, em
    except urllib.error.HTTPError as e:
        return False, e.code, str(e)
    except Exception as e:
        return False, -1, str(e)

# Danh sách mẫu dịch vụ & Client-Info
CANDIDATES = [
    # ─── 1. Apple Developer App (Dành cho Developer) ───
    ("Apple Developer App (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Developer/10.4 (10.4.0)>", 
     "Developer/10.4 (com.apple.Developer; build:10.4.0; iOS 17.6.1) Alamofire/5.4.0", "iCloud"),

    ("Apple Developer App (iPadOS 17)", 
     "<iPad14,8> <iPadOS;17.5.1;21F90> <com.apple.Developer/10.4 (10.4.0)>", 
     "Developer/10.4 (com.apple.Developer; build:10.4.0; iPadOS 17.5.1)", "iCloud"),

    # ─── 2. Apple Music (Android & iOS) ───
    ("Apple Music Android 4.7 (Pixel 8)", 
     "<Pixel 8 Pro> <Android;14;UP1A.231005.007> <com.apple.android.music/4.7.0 (1400)>", 
     "AppleMusic/4.7.0 (Android;14)", "iTunes"),

    ("Apple Music Android 4.6 (Galaxy S24)", 
     "<SM-S928B> <Android;14;UP1A.231005.007> <com.apple.android.music/4.6.0 (1320)>", 
     "AppleMusic/4.6.0 (Android;14)", "iTunes"),

    ("Apple Music iOS (Music app)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Music/1.0 (com.apple.Music/1.0)>", 
     "Music/1.0 (iOS 17.6.1; iPhone16,1)", "iTunes"),

    # ─── 3. App Store & iTunes ───
    ("App Store (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AppStore/3.0 (com.apple.AppStore/3.0)>", 
     "AppStore/3.0 (iOS;17.6.1)", "iTunes"),

    ("iTunes Store (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.itunesstored/1.0 (com.apple.itunesstored/1.0)>", 
     "itunesstored/1.0 (iOS;17.6.1)", "iTunes"),

    ("iTunes Windows 12.13", 
     "<PC> <Windows;10.0.19045;SP0.0> <com.apple.iTunes/12.13.2 (12132.3)>", 
     "iTunes/12.13.2 (Windows; N)", "iTunes"),

    # ─── 4. TestFlight & Configurator ───
    ("TestFlight (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.TestFlight/3.5.0 (3.5.0)>", 
     "TestFlight/3.5.0 (iOS;17.6.1)", "iTunes"),

    ("Apple Configurator (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.configurator/1.1 (1.1)>", 
     "Configurator/1.1 (iOS;17.6.1)", "iCloud"),

    # ─── 5. Apple TV ───
    ("Apple TV (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.tv/1.0 (com.apple.tv/1.0)>", 
     "AppleTV/1.0 (iOS;17.6.1)", "iTunes"),

    ("Apple TV Android TV (Chromecast)", 
     "<Chromecast> <Android;12;STTE.220626.001> <com.apple.atve.androidtv.appletv/1.3.1 (100)>", 
     "AppleTV/1.3.1 (Android;12)", "iTunes"),

    # ─── 6. AuthKit mặc định ───
    ("AuthKit iOS 17.5.1 (iPhone 15)", 
     "<iPhone15,4> <iOS;17.5.1;21F90> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", 
     "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0", "iCloud"),

    # ─── 7. Mẫu bị chặn (để đối chiếu) ───
    ("Xcode 16 Native (macOS 15) [Đối chiếu]", 
     "<Mac15,3> <macOS;15.0;24A335> <com.apple.dt.Xcode/16.0 (16A242d)>", 
     "Xcode/16.0", "iCloud"),

    ("macOS 14.5 Safari [Đối chiếu]", 
     "<MacBookPro18,1> <macOS;14.5;23F79> <com.apple.Safari/17.5 (17.5)>", 
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "iCloud"),
]

def main():
    print("=" * 80)
    print("  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO & SERVICES PROBER")
    print("=" * 80)
    print("[*] Đang kết nối lấy Anisette headers...")
    ani, srv = fetch_anisette()
    print(f"[*] Kết nối thành công tới server: {srv}")
    print(f"[*] Anisette Device-ID: {ani.get('X-Mme-Device-Id', 'None')[:18]}...")
    print(f"[*] Tổng số mẫu kiểm tra: {len(CANDIDATES)}")
    print("-" * 80)

    passed = []
    failed = []

    for idx, (label, ci, ua, svct) in enumerate(CANDIDATES, 1):
        print(f"[{idx:02d}/{len(CANDIDATES):02d}] {label:<45} ... ", end="", flush=True)
        ok, ec, em = test_single_client_info(ci, ua, svct, ani)
        if ok:
            print(f"\033[92m✅ OK\033[0m (ec={ec})")
            passed.append((label, ci, ua, svct))
        else:
            print(f"\033[91m❌ CHẶN\033[0m (ec={ec})")
            failed.append((label, ci, ua, svct, ec, em))
        time.sleep(0.4)

    print("=" * 80)
    print(f"  KẾT QUẢ: \033[92m{len(passed)} HỢP LỆ (MỞ CỬA)\033[0m | \033[91m{len(failed)} BỊ CHẶN\033[0m")
    print("=" * 80)

    print("\n\033[92m🟢 TOP CÁC DỊCH VỤ APPLE MỞ CỬA CHO QUA 100%:\033[0m")
    for label, ci, ua, svct in passed:
        print(f"  • \033[1m{label}\033[0m [svct={svct}]")
        print(f"    Client-Info: {ci}")
        print(f"    User-Agent:  {ua}\n")

    if failed:
        print("\033[91m🔴 CÁC MẪU BỊ APPLE TỪ CHỐI:\033[0m")
        for label, ci, ua, svct, ec, em in failed:
            print(f"  • {label} -> Mã lỗi ec={ec} ({em})")

if __name__ == "__main__":
    main()
