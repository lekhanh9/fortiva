#!/usr/bin/env python3
"""
=============================================================================
  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO PROBER & SRP AUTHENTICATOR
=============================================================================
Công cụ 2-trong-1:
  1. QUÉT (Probe): Kiểm tra tương thích Client-Info / Services với Apple GSA
                   mà KHÔNG CẦN nhập mật khẩu.
  2. ĐĂNG NHẬP (Login): Xác thực tài khoản Apple ID hoàn chỉnh bằng giao thức
                        GrandSlam SRP-6a, hỗ trợ 2FA (Trusted Device & SMS)
                        và giải mã lấy Session Token / Xcode AppToken.
=============================================================================
"""

import sys
import os
import json
import ssl
import time
import uuid
import base64
import random
import getpass
import hashlib
import hmac
import plistlib
import argparse
import urllib.request
import urllib.error
import secrets

# Kiểm tra thư viện cryptography để giải mã SPD (CBC) và AppToken (GCM)
try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ANSI Color codes
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
C_CYAN = "\033[36m"
C_WHITE = "\033[37m"

# SRP 2048 parameters (Apple GrandSlam standard RFC 5054)
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

# Apple Endpoints
GSA_URL = "https://gsa.apple.com/grandslam/GsService2"
GSA_VALIDATE_URL = "https://gsa.apple.com/grandslam/GsService2/validate"
TRUSTED_DEVICE_URL = "https://gsa.apple.com/auth/verify/trusteddevice"
PHONE_VERIFY_URL = "https://gsa.apple.com/auth/verify/phone"
PHONE_CODE_URL = "https://gsa.apple.com/auth/verify/phone/securitycode"
APP_XCODE_AUTH = "com.apple.gs.xcode.auth"

# Anisette Servers
ANISETTE_SERVERS = [
    "https://ani.sidestore.io",
    "https://anisette-v3-server-aexk.onrender.com",
    "https://ani.sidestore.app",
    "http://localhost:6969",
]

# Client-Info Profiles
CLIENT_PROFILES = [
    {
        "id": "pixel7_akd",
        "name": "Pixel 7 Android 14 (AuthKit akd) [Chuẩn iLoader / isideload]",
        "client_info": "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/808.1.4",
        "svct": "iCloud"
    },
    {
        "id": "iphone16_akd",
        "name": "iPhone 16 iOS 17.6 (AuthKit akd) [Apple ID & Developer]",
        "client_info": "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
        "svct": "iCloud"
    },
    {
        "id": "pixel8",
        "name": "Pixel 8 Pro Android 14 (Apple Music)",
        "client_info": "<Pixel 8 Pro> <Android;14;UP1A.231005.007> <com.apple.android.music/4.6.0 (1320)>",
        "user_agent": "AppleMusic/4.6.0 (Android;14)",
        "svct": "iCloud"
    },
    {
        "id": "iphone16_dev",
        "name": "iPhone 16 iOS 17.6 (Apple Developer App)",
        "client_info": "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Developer/10.4 (10.4.0)>",
        "user_agent": "Developer/10.4 (com.apple.Developer; build:10.4.0; iOS 17.6.1) Alamofire/5.4.0",
        "svct": "iCloud"
    },
    {
        "id": "ipad_dev",
        "name": "iPad Air M2 iPadOS 17.5 (Apple Developer App)",
        "client_info": "<iPad14,8> <iPadOS;17.5.1;21F90> <com.apple.Developer/10.4 (10.4.0)>",
        "user_agent": "Developer/10.4 (com.apple.Developer; build:10.4.0; iPadOS 17.5.1)",
        "svct": "iCloud"
    },
    {
        "id": "iphone15_akd",
        "name": "iPhone 15 iOS 17.5 (AuthKit akd)",
        "client_info": "<iPhone15,4> <iOS;17.5.1;21F90> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        "user_agent": "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
        "svct": "iCloud"
    }
]

# Danh sách kiểm tra probe
PROBE_CANDIDATES = [
    ("Apple Developer App (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Developer/10.4 (10.4.0)>", 
     "Developer/10.4 (com.apple.Developer; build:10.4.0; iOS 17.6.1) Alamofire/5.4.0", "iCloud"),

    ("Apple Developer App (iPadOS 17)", 
     "<iPad14,8> <iPadOS;17.5.1;21F90> <com.apple.Developer/10.4 (10.4.0)>", 
     "Developer/10.4 (com.apple.Developer; build:10.4.0; iPadOS 17.5.1)", "iCloud"),

    ("Apple Music Android 4.7 (Pixel 8)", 
     "<Pixel 8 Pro> <Android;14;UP1A.231005.007> <com.apple.android.music/4.7.0 (1400)>", 
     "AppleMusic/4.7.0 (Android;14)", "iTunes"),

    ("Apple Music Android 4.6 (Galaxy S24)", 
     "<SM-S928B> <Android;14;UP1A.231005.007> <com.apple.android.music/4.6.0 (1320)>", 
     "AppleMusic/4.6.0 (Android;14)", "iTunes"),

    ("Apple Music iOS (Music app)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Music/1.0 (com.apple.Music/1.0)>", 
     "Music/1.0 (iOS 17.6.1; iPhone16,1)", "iTunes"),

    ("App Store (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.AppStore/3.0 (com.apple.AppStore/3.0)>", 
     "AppStore/3.0 (iOS;17.6.1)", "iTunes"),

    ("iTunes Store (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.itunesstored/1.0 (com.apple.itunesstored/1.0)>", 
     "itunesstored/1.0 (iOS;17.6.1)", "iTunes"),

    ("iTunes Windows 12.13", 
     "<PC> <Windows;10.0.19045;SP0.0> <com.apple.iTunes/12.13.2 (12132.3)>", 
     "iTunes/12.13.2 (Windows; N)", "iTunes"),

    ("TestFlight (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.TestFlight/3.5.0 (3.5.0)>", 
     "TestFlight/3.5.0 (iOS;17.6.1)", "iTunes"),

    ("Apple Configurator (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.configurator/1.1 (1.1)>", 
     "Configurator/1.1 (iOS;17.6.1)", "iCloud"),

    ("Apple TV (iOS 17)", 
     "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.tv/1.0 (com.apple.tv/1.0)>", 
     "AppleTV/1.0 (iOS;17.6.1)", "iTunes"),

    ("Apple TV Android TV (Chromecast)", 
     "<Chromecast> <Android;12;STTE.220626.001> <com.apple.atve.androidtv.appletv/1.3.1 (100)>", 
     "AppleTV/1.3.1 (Android;12)", "iTunes"),

    ("AuthKit iOS 17.5.1 (iPhone 15)", 
     "<iPhone15,4> <iOS;17.5.1;21F90> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", 
     "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0", "iCloud"),

    ("Xcode 16 Native (macOS 15) [Đối chiếu]", 
     "<MacBookPro18,1> <macOS;15.0;24A335> <com.apple.dt.Xcode/16.0 (16A242d)>", 
     "Xcode/16.0 (16A242d)", "iCloud"),

    ("macOS 14.5 Safari [Đối chiếu]", 
     "<MacBookPro18,1> <macOS;14.5;23F79> <com.apple.akd/1.0 (com.apple.akd/1.0)>", 
     "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0", "iCloud"),
]


# =============================================================================
#   HELPER FUNCTIONS
# =============================================================================

def pad_to_n(val) -> bytes:
    """Pad integer hoặc bytes về đúng 256 bytes (N_LEN)"""
    if isinstance(val, int):
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    elif isinstance(val, bytes):
        val_bytes = val
    else:
        raise TypeError(f"Invalid type for pad_to_n: {type(val)}")
    return val_bytes.rjust(256, b"\x00")

def natural_bytes(val_int: int) -> bytes:
    """Lấy big-endian bytes tự nhiên không chứa số 0 padding dư thừa"""
    length = (val_int.bit_length() + 7) // 8
    return val_int.to_bytes(max(1, length), byteorder="big")

def extract_bytes(val) -> bytes:
    """Trích xuất bytes từ bytes hoặc chuỗi base64"""
    if val is None:
        return b""
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        try:
            return base64.b64decode(val)
        except Exception:
            return val.encode("utf-8")
    return bytes(val)

def ensure_plist_wrapper(data: bytes) -> bytes:
    """Bọc thẻ plist XML nếu server trả về thiếu wrapper ngoài cùng"""
    stripped = data.strip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"bplist"):
        return data
    header = (
        b"<?xml version='1.0' encoding='UTF-8'?>\n"
        b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
        b"<plist version='1.0'>\n"
    )
    footer = b"\n</plist>"
    return header + data + footer

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


# =============================================================================
#   DECRYPTION (AES-256-CBC & AES-256-GCM)
# =============================================================================

def decrypt_cbc(session_key: bytes, data: bytes) -> bytes:
    """Giải mã payload SPD bằng AES-256-CBC và unpad PKCS7"""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cần cài cryptography (pip install cryptography) để giải mã SPD")
    
    key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:16]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()
    
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        pad_len = padded[-1]
        if 1 <= pad_len <= 16:
            return padded[:-pad_len]
        return padded

def decrypt_gcm(sk: bytes, encrypted_data: bytes) -> bytes:
    """Giải mã AppToken et bằng AES-256-GCM (Apple dùng nonce 16-byte và AAD='XYZ')"""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cần cài cryptography (pip install cryptography) để giải mã AppToken")
    
    if len(encrypted_data) < 35:
        raise ValueError(f"Dữ liệu mã hóa quá ngắn ({len(encrypted_data)} bytes)")
    if encrypted_data[:3] != b"XYZ":
        raise ValueError(f"Tiền tố token không hợp lệ (cần 'XYZ'): {encrypted_data[:3]}")

    aad = encrypted_data[:3]
    iv = encrypted_data[3:19]  # 16 bytes nonce
    ciphertext = encrypted_data[19:-16]
    tag = encrypted_data[-16:]

    cipher = Cipher(algorithms.AES(sk), modes.GCM(iv, tag))
    dec = cipher.decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ciphertext) + dec.finalize()


# =============================================================================
#   GRANDSLAM GSA NETWORK CLIENT
# =============================================================================

def gsa_request(params: dict, client_info: str, ani: dict, ua: str, svct: str = "iCloud", extra_headers: dict = None, retries: int = 3) -> dict:
    """Gửi request XML Plist lên GSA endpoint và trả về dict 'Response'"""
    op = params.get("o", "?")
    device_id = ani.get("X-Mme-Device-Id", str(uuid.uuid4()).upper())
    user_id = str(uuid.uuid4()).upper()

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    client_time = ani.get("X-Apple-I-Client-Time", now_iso)

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
        "X-Apple-I-Client-Time": client_time,
        "X-Apple-I-TimeZone": "UTC",
        "X-MMe-Client-Info": client_info,
    }

    req_dict = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "cpd": cpd,
            **params
        }
    }

    body_bytes = plistlib.dumps(req_dict)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": ua,
        "X-Mme-Client-Info": client_info,
        "Connection": "close"  # Đóng kết nối tránh 429 rate limit
    }
    if extra_headers:
        headers.update(extra_headers)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    effective_retries = 1 if op == "apptokens" else retries

    for attempt in range(effective_retries):
        try:
            req = urllib.request.Request(GSA_URL, data=body_bytes, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                resp_bytes = resp.read()
                wrapped = ensure_plist_wrapper(resp_bytes)
                parsed = plistlib.loads(wrapped)
                return parsed.get("Response", {})
        except urllib.error.HTTPError as e:
            err_body = e.read()
            if e.code == 429:
                print(f"{C_YELLOW}[!] GSA báo HTTP 429 (Rate limit) - Chờ 10s... ({attempt + 1}/{effective_retries}){C_RESET}")
                time.sleep(10)
                continue
            try:
                wrapped = ensure_plist_wrapper(err_body)
                parsed = plistlib.loads(wrapped)
                if "Response" in parsed:
                    return parsed["Response"]
            except Exception:
                pass
            if attempt + 1 >= effective_retries:
                raise RuntimeError(f"GSA HTTP Error {e.code}: {e.reason}")
            time.sleep(2)
        except Exception as e:
            if attempt + 1 >= effective_retries:
                raise
            time.sleep(2)

    raise RuntimeError(f"GSA request '{op}' thất bại sau {effective_retries} lần thử")


# =============================================================================
#   2FA HANDLERS (TRUSTED DEVICE & SMS)
# =============================================================================

def handle_trusted_device_2fa(ani: dict, client_info: str, dsid: str, idms_token: str, already_sent: bool = False) -> bool:
    """Gửi Push 2FA đến các thiết bị Apple tin cậy và xác thực mã 6 số"""
    device_id = ani.get("X-Mme-Device-Id", str(uuid.uuid4()).upper())
    identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "User-Agent": "akd/1.0 CFNetwork/808.1.4",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": APP_XCODE_AUTH,
        "X-Xcode-Version": "14.2 (14C18)",
        "X-Mme-Client-Info": client_info,
        "X-Apple-I-DSID": str(dsid),
        "X-Apple-I-MD": ani.get("X-Apple-I-MD", ""),
        "X-Apple-I-MD-M": ani.get("X-Apple-I-MD-M", ""),
        "X-Apple-I-MD-LU": base64.b64encode(str(dsid).encode()).decode(),
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-Client-Time": ani.get("X-Apple-I-Client-Time", ""),
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": "en_US",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if already_sent:
        print(f"\n{C_MAGENTA}{C_BOLD}[2FA] 📱 Apple đã tự động gửi mã xác minh 2FA tới thiết bị Apple của bạn!{C_RESET}")
    else:
        print(f"\n{C_CYAN}[2FA] Đang gửi yêu cầu Push mã 2FA tới thiết bị Apple tin cậy...{C_RESET}")
        push_sent = False
        for attempt in range(3):
            try:
                req = urllib.request.Request(TRUSTED_DEVICE_URL, headers=headers)
                with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                    if resp.status in (200, 412):
                        print(f"{C_GREEN}[+] Đã gửi tín hiệu Push 2FA thành công!{C_RESET}")
                        push_sent = True
                        break
            except urllib.error.HTTPError as e:
                if e.code in (200, 412):
                    push_sent = True
                    break
                time.sleep(2)
            except Exception:
                time.sleep(2)

        if not push_sent:
            print(f"{C_YELLOW}[!] Push có thể đã gửi (hoặc kiểm tra thiết bị iPhone/iPad/Mac của bạn){C_RESET}")

    # Vòng lặp nhập mã (cho phép thử lại tối đa 3 lần nếu nhập sai mã)
    for attempt in range(1, 4):
        prompt = "[?] Nhập mã 6 số hiển thị trên thiết bị Apple: " if attempt == 1 else "[?] Nhập lại mã 6 số: "
        code = input(f"{C_BOLD}{C_YELLOW}{prompt}{C_RESET}").strip()
        if not code:
            print(f"{C_RED}[-] Đã hủy nhập mã 2FA.{C_RESET}")
            return False

        verify_headers = dict(headers)
        verify_headers["security-code"] = code

        try:
            req = urllib.request.Request(GSA_VALIDATE_URL, data=b"", headers=verify_headers)
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                resp_body = resp.read()
                wrapped = ensure_plist_wrapper(resp_body)
                parsed = plistlib.loads(wrapped)
                ec = parsed.get("Response", {}).get("Status", {}).get("ec", 0)
                if ec == 0 or resp.status == 200:
                    print(f"{C_GREEN}{C_BOLD}[+] Xác thực mã 2FA thành công!{C_RESET}")
                    return True
                elif ec == -21669:
                    print(f"{C_RED}[-] Mã xác minh 2FA không chính xác (-21669). Vui lòng thử lại!{C_RESET}")
                    continue
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                parsed = plistlib.loads(ensure_plist_wrapper(body))
                ec = parsed.get("Response", {}).get("Status", {}).get("ec", 0)
                if ec == 0:
                    print(f"{C_GREEN}{C_BOLD}[+] Xác thực mã 2FA thành công!{C_RESET}")
                    return True
                elif ec == -21669:
                    print(f"{C_RED}[-] Mã xác minh 2FA không chính xác (-21669). Vui lòng thử lại!{C_RESET}")
                    continue
            except Exception:
                pass
            print(f"{C_RED}[-] Lỗi xác thực (HTTP {e.code}).{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[-] Lỗi kết nối 2FA: {e}{C_RESET}")

    return False


# =============================================================================
#   SRP-6A LOGIN AUTHENTICATION WORKFLOW
# =============================================================================

def perform_srp_login(username: str, password: str, profile: dict, depth: int = 0) -> dict:
    """Thực hiện chu trình đăng nhập GrandSlam SRP-6a hoàn chỉnh"""
    if depth > 0:
        print(f"\n{C_CYAN}[*] Tiếp tục hoàn tất đăng nhập sau 2FA (lần {depth})...{C_RESET}")
    else:
        print(f"\n{C_BOLD}{C_BLUE}[*] Bắt đầu xác thực Apple ID: {username}{C_RESET}")
        print(f"[*] Cấu hình Client-Info: {profile['name']}")

    # 1. Lấy Anisette
    print("[*] Đang kết nối lấy Anisette headers...")
    ani, ani_url = fetch_anisette()
    print(f"{C_GREEN}[+] Kết nối Anisette thành công: {ani_url}{C_RESET}")

    client_info = profile["client_info"]
    ua = profile["user_agent"]
    svct = profile["svct"]

    # 2. Sinh cặp khóa công khai SRP A
    # a: số ngẫu nhiên 256 bits (32 bytes)
    a_bytes = secrets.token_bytes(32)
    a = int.from_bytes(a_bytes, byteorder="big")
    A = pow(g, a, N)
    A_bytes = pad_to_n(A)

    # 3. Gửi Init Request (o = "init")
    print("[*] [1/3] Đang gửi SRP Init handshake lên gsa.apple.com...")
    init_params = {
        "A2k": A_bytes,
        "ps": ["s2k", "s2k_fo"],
        "u": username,
        "o": "init",
        "svct": svct
    }

    init_resp = gsa_request(init_params, client_info, ani, ua, svct=svct)
    status = init_resp.get("Status", {})
    ec = status.get("ec", 0)
    if ec != 0:
        em = status.get("em", "Unknown error")
        raise RuntimeError(f"GSA Init thất bại (ec={ec}): {em}")

    protocol = init_resp.get("sp", "s2k")
    salt = extract_bytes(init_resp.get("s"))
    b_pub_bytes = extract_bytes(init_resp.get("B"))
    c_challenge = init_resp.get("c")
    iterations = int(init_resp.get("i", 20000))

    if not salt or not b_pub_bytes or not c_challenge:
        raise RuntimeError(f"Init response thiếu dữ liệu cần thiết (s={bool(salt)}, B={bool(b_pub_bytes)}, c={bool(c_challenge)})")

    print(f"{C_GREEN}[+] SRP Init thành công (protocol={protocol}, iterations={iterations}, salt_len={len(salt)}){C_RESET}")

    # 4. Tính toán SRP Challenge Response
    print("[*] Đang tính toán PBKDF2 & SRP proof (M1)...")
    B = int.from_bytes(b_pub_bytes, byteorder="big")

    # k = SHA256(PAD(N) || PAD(g))
    k_bytes = hashlib.sha256(pad_to_n(N) + pad_to_n(g)).digest()
    k = int.from_bytes(k_bytes, byteorder="big")

    # u = SHA256(PAD(A) || PAD(B))
    u_bytes = hashlib.sha256(pad_to_n(A) + pad_to_n(B)).digest()
    u = int.from_bytes(u_bytes, byteorder="big")

    # p = PBKDF2(SHA256(password), salt, iterations)
    pw_hash = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        pw_hash = pw_hash.hex().encode("utf-8")
    
    p = hashlib.pbkdf2_hmac("sha256", pw_hash, salt, iterations, dklen=32)

    # x = SHA256(salt || SHA256(":" || p))
    inner = hashlib.sha256(b":" + p).digest()
    x_bytes = hashlib.sha256(salt + inner).digest()
    x = int.from_bytes(x_bytes, byteorder="big")

    # S = (B - k * g^x) ^ (a + u * x) mod N
    g_x = pow(g, x, N)
    k_g_x = (k * g_x) % N
    base = (B - k_g_x) % N
    exp = a + u * x
    S = pow(base, exp, N)
    S_padded = pad_to_n(S)

    # K = SHA256(PAD(S))
    session_key = hashlib.sha256(S_padded).digest()

    # M1 = SHA256( H(N) XOR H(g) || H(username) || salt || A_natural || B_natural || K )
    h_n = hashlib.sha256(pad_to_n(N)).digest()
    h_g = hashlib.sha256(pad_to_n(g)).digest()
    h_xor = bytes(x_b ^ y_b for x_b, y_b in zip(h_n, h_g))
    h_user = hashlib.sha256(username.encode("utf-8")).digest()

    a_natural = natural_bytes(A)
    b_natural = natural_bytes(B)

    m1 = hashlib.sha256(h_xor + h_user + salt + a_natural + b_natural + session_key).digest()

    # 5. Gửi Complete Request (o = "complete")
    print("[*] [2/3] Đang gửi SRP Complete proof lên gsa.apple.com...")
    complete_params = {
        "c": c_challenge,
        "M1": m1,
        "u": username,
        "o": "complete",
        "svct": svct
    }

    complete_resp = gsa_request(complete_params, client_info, ani, ua, svct=svct)
    comp_status = complete_resp.get("Status", {})
    comp_ec = comp_status.get("ec", 0)
    auth_type = comp_status.get("au")

    # Kiểm tra M2 proof từ server
    if "M2" in complete_resp:
        m2_server = extract_bytes(complete_resp.get("M2"))
        expected_m2 = hashlib.sha256(a_natural + m1 + session_key).digest()
        if m2_server == expected_m2:
            print(f"{C_GREEN}[+] Server proof M2 xác thực HỢP LỆ!{C_RESET}")
        else:
            print(f"{C_YELLOW}[!] Server proof M2 mismatch.{C_RESET}")

    # Giải mã SPD nếu có
    spd_dict = {}
    if "spd" in complete_resp:
        spd_raw = extract_bytes(complete_resp.get("spd"))
        if spd_raw and HAS_CRYPTOGRAPHY:
            try:
                decrypted_spd = decrypt_cbc(session_key, spd_raw)
                spd_dict = plistlib.loads(decrypted_spd)
                print(f"{C_GREEN}[+] Giải mã SPD payload thành công ({len(spd_dict)} keys).{C_RESET}")
            except Exception as e:
                print(f"{C_YELLOW}[!] Giải mã SPD payload thất bại: {e}{C_RESET}")

    hsc = comp_status.get("hsc", 200)
    spd_status = spd_dict.get("status-code")
    spd_authmode = spd_dict.get("authmode")

    # Trích xuất au đa tầng: Status -> Response -> SPD (au) -> SPD (authmode)
    auth_type = (
        comp_status.get("au")
        or complete_resp.get("au")
        or spd_dict.get("au")
        or (spd_authmode if spd_authmode != "password" else None)
    )

    if not auth_type and (hsc == 409 or spd_status == 409):
        auth_type = spd_authmode or "trustedDeviceSecondaryAuth"

    # Kiểm tra lỗi tài khoản
    if comp_ec != 0 and not auth_type:
        em = comp_status.get("em", "Tài khoản hoặc mật khẩu không chính xác")
        raise RuntimeError(f"Xác thực thất bại (ec={comp_ec}): {em}")

    # 6. Xử lý 2FA nếu có yêu cầu
    if auth_type and any(k in str(auth_type) for k in ("SecondaryAuth", "secondaryAuth", "trustedDeviceSecondaryAuth", "smsSecondaryAuth")):
        print(f"\n{C_MAGENTA}{C_BOLD}[!] Apple yêu cầu xác minh 2FA: {auth_type}{C_RESET}")
        dsid = str(spd_dict.get("adsid") or spd_dict.get("dsid") or comp_status.get("dsid") or "")
        idms_token = str(spd_dict.get("GsIdmsToken") or spd_dict.get("idmsToken") or comp_status.get("idmsToken") or "")

        if not dsid or not idms_token:
            raise RuntimeError("Thiếu DSID hoặc IDMS-Token để thực hiện bước 2FA!")

        already_sent = (hsc == 409 or spd_status == 409)
        if not already_sent:
            time.sleep(2)

        twofa_ok = handle_trusted_device_2fa(ani, client_info, dsid, idms_token, already_sent=already_sent)
        if not twofa_ok:
            raise RuntimeError("Xác thực 2FA không thành công.")

        if depth >= 1:
            print(f"{C_YELLOW}[*] Đã hoàn tất xác thực 2FA.{C_RESET}")
        else:
            print(f"{C_CYAN}[*] 2FA OK! Tự động đăng nhập lại sau 2s để lấy token phiên...{C_RESET}")
            time.sleep(2)
            return perform_srp_login(username, password, profile, depth=depth + 1)

    # 7. Trích xuất thông tin phiên đăng nhập
    adsid = str(spd_dict.get("adsid") or spd_dict.get("dsid") or comp_status.get("dsid") or "")
    idms_token = str(spd_dict.get("GsIdmsToken") or spd_dict.get("idmsToken") or "")
    c_resp = spd_dict.get("c") or complete_resp.get("c")
    sk = extract_bytes(spd_dict.get("sk"))

    auth_result = {
        "username": username,
        "dsid": adsid,
        "idms_token": idms_token,
        "app_token": None,
        "client_info": client_info,
        "session_timestamp": time.time()
    }

    # 8. Yêu cầu AppToken (com.apple.gs.xcode.auth)
    if adsid and c_resp and idms_token and sk and HAS_CRYPTOGRAPHY:
        print("\n[*] [3/3] Đang gửi yêu cầu lấy Xcode AppToken (com.apple.gs.xcode.auth)...")
        time.sleep(2)
        try:
            # Checksum = HMAC-SHA256(sk, "apptokens" || adsid || app)
            mac = hmac.new(sk, b"apptokens" + adsid.encode("utf-8") + APP_XCODE_AUTH.encode("utf-8"), hashlib.sha256)
            checksum = mac.digest()

            app_params = {
                "u": adsid,
                "app": [APP_XCODE_AUTH],
                "c": c_resp,
                "t": idms_token,
                "checksum": checksum,
                "o": "apptokens",
                "svct": svct
            }

            token_resp = gsa_request(app_params, client_info, ani, ua, svct=svct, retries=1)
            token_ec = token_resp.get("Status", {}).get("ec", 0)

            # Nếu Apple yêu cầu 2FA (-22411) ngay tại bước AppToken
            if token_ec == -22411:
                print(f"\n{C_MAGENTA}{C_BOLD}[2FA] 📱 Apple đã gửi mã xác minh 2FA (-22411) tới thiết bị Apple của bạn!{C_RESET}")
                code = input(f"{C_BOLD}{C_YELLOW}[?] Nhập mã 6 số hiển thị trên iPhone/iPad: {C_RESET}").strip()
                if code:
                    print("[2FA] Đang gửi mã xác thực lên Apple...")
                    verify_headers = {
                        "Content-Type": "text/x-xml-plist",
                        "Accept": "text/x-xml-plist",
                        "User-Agent": "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0",
                        "Accept-Language": "en-us",
                        "X-Apple-Identity-Token": base64.b64encode(f"{adsid}:{idms_token}".encode()).decode(),
                        "X-Apple-App-Info": APP_XCODE_AUTH,
                        "X-Xcode-Version": "14.2 (14C18)",
                        "X-Mme-Client-Info": client_info,
                        "X-Apple-I-DSID": str(adsid),
                        "security-code": code,
                    }
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        v_req = urllib.request.Request(GSA_VALIDATE_URL, data=b"", headers=verify_headers)
                        with urllib.request.urlopen(v_req, context=ctx, timeout=15) as v_resp:
                            if v_resp.status in (200, 204):
                                print(f"{C_GREEN}[+] Xác thực 2FA thành công! Đang lấy AppToken...{C_RESET}")
                                time.sleep(2)
                                token_resp = gsa_request(app_params, client_info, ani, ua, svct=svct, retries=1)
                    except Exception as ve:
                        print(f"{C_RED}[-] Xác thực 2FA thất bại: {ve}{C_RESET}")

            et = extract_bytes(token_resp.get("et"))
            if et:
                decrypted_et = decrypt_gcm(sk, et)
                et_plist = plistlib.loads(decrypted_et)
                token_val = et_plist.get("t", {}).get(APP_XCODE_AUTH, {}).get("token")
                if token_val:
                    print(f"{C_GREEN}{C_BOLD}[+] Nhận AppToken thành công!{C_RESET}")
                    auth_result["app_token"] = token_val
                    test_developer_api(adsid, token_val, ani)
        except Exception as e:
            print(f"{C_YELLOW}[!] Lỗi lấy AppToken: {e}{C_RESET}")

    return auth_result


def test_developer_api(adsid: str, app_token: str, ani: dict):
    """Kiểm tra gọi Apple Developer Services API (listTeams) bằng AppToken vừa nhận"""
    print(f"\n{C_BOLD}{C_BLUE}[*] Đang kiểm tra quyền Apple Developer API (listTeams)...{C_RESET}")
    dev_url = "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA"
    req_id = str(uuid.uuid4()).upper()

    dev_body = {
        "clientId": "XABBG36SBA",
        "protocolVersion": "QH65B2",
        "requestId": req_id,
        "userLocale": ["en_US"]
    }
    xml_data = plistlib.dumps(dev_body)

    device_id = ani.get("X-Mme-Device-Id", str(uuid.uuid4()).upper())
    dev_ci = "<iPhone16,1> <iOS;17.6.1;21G93> <com.apple.Developer/10.4 (10.4.0)>"
    dev_ua = "Developer/10.4 (com.apple.Developer; build:10.4.0; iOS 17.6.1) Alamofire/5.4.0"

    dev_headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "User-Agent": dev_ua,
        "X-Mme-Client-Info": dev_ci,
        "X-MMe-Client-Info": dev_ci,
        "X-Apple-GS-Token": app_token,
        "X-Apple-I-Identity-Id": str(adsid),
        "X-Xcode-Version": "14.2 (14C18)",
        "X-Apple-I-MD": ani.get("X-Apple-I-MD", ""),
        "X-Apple-I-MD-M": ani.get("X-Apple-I-MD-M", ""),
        "X-Apple-I-MD-LU": base64.b64encode(str(adsid).encode()).decode(),
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-Client-Time": ani.get("X-Apple-I-Client-Time", ""),
        "X-Apple-I-TimeZone": "UTC",
        "Connection": "close"
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(dev_url, data=xml_data, headers=dev_headers)
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            resp_body = resp.read()
            parsed = plistlib.loads(ensure_plist_wrapper(resp_body))
            rc = parsed.get("resultCode", -1)
            teams = parsed.get("teams", [])
            if rc == 0:
                print(f"{C_GREEN}{C_BOLD}[+] Kết nối Apple Developer Services API THÀNH CÔNG!{C_RESET}")
                print(f"  • Số lượng Team tìm thấy: {len(teams)}")
                for t in teams:
                    t_name = t.get("name", "N/A")
                    t_id = t.get("teamId", "N/A")
                    t_type = t.get("type", "Individual")
                    print(f"    - [{t_id}] {t_name} ({t_type})")
                return teams
            else:
                user_str = parsed.get("userString") or parsed.get("resultString", f"resultCode: {rc}")
                print(f"{C_YELLOW}[!] Apple Developer API phản hồi (rc={rc}): {user_str}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}[-] Lỗi gọi Apple Developer API: {e}{C_RESET}")
    return None


# =============================================================================
#   PROBE CLIENT-INFO WORKFLOW
# =============================================================================

def run_probe():
    """Chạy quét tự động tất cả các mẫu Client-Info và Services"""
    print("=" * 80)
    print(f"{C_BOLD}{C_GREEN}  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO & SERVICES PROBER{C_RESET}")
    print("=" * 80)
    print("[*] Đang kết nối lấy Anisette headers...")
    try:
        ani, server = fetch_anisette()
        print(f"{C_GREEN}[*] Kết nối thành công tới server: {server}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}[-] Lỗi Anisette: {e}{C_RESET}")
        return

    print(f"[*] Anisette Device-ID: {ani.get('X-Mme-Device-Id', '')[:18]}...")
    print(f"[*] Tổng số mẫu kiểm tra: {len(PROBE_CANDIDATES)}")
    print("-" * 80)

    results = []
    for idx, (name, ci, ua, svct) in enumerate(PROBE_CANDIDATES, 1):
        sys.stdout.write(f"[{idx:02d}/{len(PROBE_CANDIDATES):02d}] {name:<45} ... ")
        sys.stdout.flush()

        user_id = str(uuid.uuid4()).upper()
        device_id = ani.get("X-Mme-Device-Id", str(uuid.uuid4()).upper())
        a = random.getrandbits(256)
        A_bytes = pad_to_n(pow(g, a, N))

        init_params = {
            "A2k": A_bytes,
            "ps": ["s2k", "s2k_fo"],
            "u": f"probe_test_{user_id[:8].lower()}@icloud.com",
            "o": "init",
            "svct": svct
        }

        try:
            resp = gsa_request(init_params, ci, ani, ua, svct=svct, retries=1)
            status = resp.get("Status", {})
            ec = status.get("ec", 0)
            em = status.get("em", "")

            if ec == -80045:
                print(f"{C_RED}❌ CHẶN (ec=-80045){C_RESET}")
                results.append((name, ci, ua, svct, False, -80045, em))
            elif ec == -20101:
                print(f"{C_GREEN}✅ OK (ec=-20101){C_RESET}")
                results.append((name, ci, ua, svct, True, -20101, em))
            else:
                print(f"{C_YELLOW}⚠️  EC={ec}{C_RESET}")
                results.append((name, ci, ua, svct, False, ec, em))
        except urllib.error.HTTPError as e:
            print(f"{C_RED}❌ CHẶN (ec={e.code}){C_RESET}")
            results.append((name, ci, ua, svct, False, e.code, str(e)))
        except Exception as e:
            print(f"{C_RED}❌ LỖI ({e}){C_RESET}")
            results.append((name, ci, ua, svct, False, -1, str(e)))

        time.sleep(0.3)

    print("=" * 80)
    passed = [r for r in results if r[4]]
    failed = [r for r in results if not r[4]]
    print(f"{C_BOLD}  KẾT QUẢ: {C_GREEN}{len(passed)} HỢP LỆ (MỞ CỬA){C_RESET} | {C_RED}{len(failed)} BỊ CHẶN{C_RESET}")
    print("=" * 80)


# =============================================================================
#   MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Apple GSA Client-Info Prober & GrandSlam SRP Login Tool")
    parser.add_argument("--probe", action="store_true", help="Chạy quét kiểm tra tương thích Client-Info")
    parser.add_argument("--login", action="store_true", help="Bắt đầu đăng nhập tài khoản Apple ID")
    parser.add_argument("-u", "--username", help="Apple ID (Email)")
    parser.add_argument("-p", "--password", help="Mật khẩu Apple ID")
    parser.add_argument("-c", "--client", default="pixel7_akd", help="Profile Client-Info (pixel7_akd, iphone16_akd, pixel8, iphone16_dev)")
    parser.add_argument("-o", "--output", help="Lưu thông tin phiên đăng nhập ra file JSON")

    args = parser.parse_args()

    # Chọn profile client
    selected_profile = next((p for p in CLIENT_PROFILES if p["id"] == args.client), CLIENT_PROFILES[0])

    if args.probe:
        run_probe()
        return

    if args.login:
        username = args.username or input(f"{C_BOLD}[?] Nhập Apple ID (Email): {C_RESET}").strip()
        password = args.password or getpass.getpass(f"{C_BOLD}[?] Nhập Mật khẩu Apple ID: {C_RESET}")
        if not username or not password:
            print(f"{C_RED}[-] Apple ID và Mật khẩu không được để trống!{C_RESET}")
            return
        try:
            res = perform_srp_login(username, password, selected_profile)
            print("\n" + "=" * 80)
            print(f"{C_GREEN}{C_BOLD}🎉 ĐĂNG NHẬP THÀNH CÔNG! THÔNG TIN PHIÊN XÁC THỰC:{C_RESET}")
            print("=" * 80)
            print(f"  • Apple ID:    {C_CYAN}{res['username']}{C_RESET}")
            print(f"  • DSID:        {C_CYAN}{res['dsid']}{C_RESET}")
            print(f"  • IDMS-Token:  {C_CYAN}{res['idms_token'][:20]}... (len={len(res['idms_token'])}){C_RESET}")
            if res.get("app_token"):
                print(f"  • AppToken:    {C_GREEN}{res['app_token'][:30]}... (len={len(res['app_token'])}){C_RESET}")
            print("=" * 80)

            out_file = args.output or "apple_session.json"
            with open(out_file, "w") as f:
                json.dump(res, f, indent=2)
            print(f"{C_GREEN}[+] Đã lưu thông tin phiên vào: {out_file}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}{C_BOLD}❌ ĐĂNG NHẬP THẤT BẠI: {e}{C_RESET}")
        return

    # Menu tương tác nếu chạy python3 probe_services.py không tham số
    print("=" * 80)
    print(f"{C_BOLD}{C_GREEN}  🍎 FORTIVA - APPLE GRANDSLAM GSA TOOLKIT{C_RESET}")
    print("=" * 80)
    print("  [1] Quét tương thích Client-Info & Services (Probe Mode - Không cần password)")
    print("  [2] Đăng nhập Apple ID đầy đủ (GrandSlam SRP + 2FA + Lấy AppToken)")
    print("  [0] Thoát")
    print("-" * 80)

    choice = input(f"{C_BOLD}Chọn tính năng [1/2/0]: {C_RESET}").strip()
    if choice == "1":
        run_probe()
    elif choice == "2":
        print(f"\n{C_BOLD}Chọn Client-Info profile:{C_RESET}")
        for idx, p in enumerate(CLIENT_PROFILES, 1):
            print(f"  [{idx}] {p['name']}")
        p_choice = input(f"Chọn profile [1-{len(CLIENT_PROFILES)}] (mặc định 1): ").strip()
        try:
            p_idx = int(p_choice) - 1
            if 0 <= p_idx < len(CLIENT_PROFILES):
                selected_profile = CLIENT_PROFILES[p_idx]
        except Exception:
            selected_profile = CLIENT_PROFILES[0]

        username = input(f"\n{C_BOLD}[?] Nhập Apple ID (Email): {C_RESET}").strip()
        password = getpass.getpass(f"{C_BOLD}[?] Nhập Mật khẩu Apple ID: {C_RESET}")
        if not username or not password:
            print(f"{C_RED}[-] Apple ID và Mật khẩu không được để trống!{C_RESET}")
            return
        try:
            res = perform_srp_login(username, password, selected_profile)
            print("\n" + "=" * 80)
            print(f"{C_GREEN}{C_BOLD}🎉 ĐĂNG NHẬP THÀNH CÔNG! THÔNG TIN PHIÊN XÁC THỰC:{C_RESET}")
            print("=" * 80)
            print(f"  • Apple ID:    {C_CYAN}{res['username']}{C_RESET}")
            print(f"  • DSID:        {C_CYAN}{res['dsid']}{C_RESET}")
            print(f"  • IDMS-Token:  {C_CYAN}{res['idms_token'][:20]}... (len={len(res['idms_token'])}){C_RESET}")
            if res.get("app_token"):
                print(f"  • AppToken:    {C_GREEN}{res['app_token'][:30]}... (len={len(res['app_token'])}){C_RESET}")
            print("=" * 80)

            out_file = "apple_session.json"
            with open(out_file, "w") as f:
                json.dump(res, f, indent=2)
            print(f"{C_GREEN}[+] Đã lưu thông tin phiên vào: {out_file}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}{C_BOLD}❌ ĐĂNG NHẬP THẤT BẠI: {e}{C_RESET}")
    else:
        print("Tạm biệt!")

if __name__ == "__main__":
    main()
