#!/usr/bin/env python3
"""
=============================================================================
  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO PROBER & SRP AUTHENTICATOR
=============================================================================
2-in-1 Toolkit:
  1. PROBE: Test Client-Info & Services compatibility with Apple GSA
            WITHOUT requiring a password.
  2. LOGIN: Complete Apple ID authentication using GrandSlam SRP-6a protocol,
            supporting 2FA (Trusted Device & SMS) and decrypting session
            tokens as well as Xcode AppTokens.
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

# Check for cryptography library to decrypt SPD (CBC) and AppToken (GCM)
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
        "name": "Pixel 7 Android 14 (AuthKit akd) [Standard iLoader / isideload]",
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

# Probe candidate list
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

    ("Xcode 16 Native (macOS 15) [Reference]", 
     "<MacBookPro18,1> <macOS;15.0;24A335> <com.apple.dt.Xcode/16.0 (16A242d)>", 
     "Xcode/16.0 (16A242d)", "iCloud"),

    ("macOS 14.5 Safari [Reference]", 
     "<MacBookPro18,1> <macOS;14.5;23F79> <com.apple.akd/1.0 (com.apple.akd/1.0)>", 
     "akd/1.0 CFNetwork/1496.0.7 Darwin/23.5.0", "iCloud"),
]


# =============================================================================
#   HELPER FUNCTIONS
# =============================================================================

def pad_to_n(val) -> bytes:
    """Pad integer or bytes to exactly 256 bytes (N_LEN)"""
    if isinstance(val, int):
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    elif isinstance(val, bytes):
        val_bytes = val
    else:
        raise TypeError(f"Invalid type for pad_to_n: {type(val)}")
    return val_bytes.rjust(256, b"\x00")

def natural_bytes(val_int: int) -> bytes:
    """Get natural big-endian bytes without redundant zero padding"""
    length = (val_int.bit_length() + 7) // 8
    return val_int.to_bytes(max(1, length), byteorder="big")

def extract_bytes(val) -> bytes:
    """Extract raw bytes from bytes or base64 string"""
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

def to_string(v) -> str:
    """Convert plist value (str, bytes, int) to clean string"""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except Exception:
            return base64.b64encode(v).decode()
    return str(v)

def ensure_plist_wrapper(data: bytes) -> bytes:
    """Wrap in plist XML tags if server returned unwrapped payload"""
    stripped = data.strip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"bplist"):
        return data
    if stripped.startswith(b"<plist"):
        return b"<?xml version='1.0' encoding='UTF-8'?>\n" + data
    header = (
        b"<?xml version='1.0' encoding='UTF-8'?>\n"
        b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
        b"<plist version='1.0'>\n"
    )
    footer = b"\n</plist>"
    return header + data + footer

def fetch_anisette():
    """Fetch Anisette headers from available servers with fallback"""
    for server in ANISETTE_SERVERS:
        try:
            req = urllib.request.urlopen(server, timeout=8)
            data = json.loads(req.read().decode())
            if "X-Apple-I-MD-M" in data:
                return data, server
        except Exception:
            continue
    raise RuntimeError("Failed to connect to any Anisette server!")


# =============================================================================
#   DECRYPTION (AES-256-CBC & AES-256-GCM)
# =============================================================================

def decrypt_cbc(session_key: bytes, data: bytes) -> bytes:
    """Decrypt SPD payload with AES-256-CBC and unpad PKCS7"""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cryptography library required (pip install cryptography) to decrypt SPD")
    
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
    """Decrypt AppToken et with AES-256-GCM (Apple uses 16-byte nonce and AAD='XYZ')"""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cryptography library required (pip install cryptography) to decrypt AppToken")
    
    if len(encrypted_data) < 35:
        raise ValueError(f"Encrypted data too short ({len(encrypted_data)} bytes)")
    if encrypted_data[:3] != b"XYZ":
        raise ValueError(f"Invalid token prefix (expected 'XYZ'): {encrypted_data[:3]}")

    aad = encrypted_data[:3]
    iv = encrypted_data[3:19]  # 16-byte nonce
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
    """Send XML Plist request to GSA endpoint and return 'Response' dict"""
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
        "Connection": "close"  # Close connection to mitigate rate limits
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
                print(f"{C_YELLOW}[!] GSA reported HTTP 429 (Rate limit) - Waiting 10s... ({attempt + 1}/{effective_retries}){C_RESET}")
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

    raise RuntimeError(f"GSA request '{op}' failed after {effective_retries} attempts")


# =============================================================================
#   2FA HANDLERS (TRUSTED DEVICE & SMS)
# =============================================================================

def handle_trusted_device_2fa(ani: dict, client_info: str, dsid: str, idms_token: str, already_sent: bool = False) -> bool:
    """Send 2FA Push notification to trusted Apple devices and verify 6-digit code"""
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
        print(f"\n{C_MAGENTA}{C_BOLD}[2FA] 📱 Apple automatically sent a 2FA verification code to your Apple device!{C_RESET}")
    else:
        print(f"\n{C_CYAN}[2FA] Requesting 2FA Push notification to trusted Apple devices...{C_RESET}")
        push_sent = False
        for attempt in range(3):
            try:
                req = urllib.request.Request(TRUSTED_DEVICE_URL, headers=headers)
                with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                    if resp.status in (200, 412):
                        print(f"{C_GREEN}[+] 2FA Push request sent successfully!{C_RESET}")
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
            print(f"{C_YELLOW}[!] Push notification may have been sent (please check your iPhone/iPad/Mac){C_RESET}")

    # Code input loop (allows up to 3 attempts on incorrect code)
    for attempt in range(1, 4):
        prompt = "[?] Enter 6-digit code shown on Apple device: " if attempt == 1 else "[?] Re-enter 6-digit code: "
        code = input(f"{C_BOLD}{C_YELLOW}{prompt}{C_RESET}").strip()
        if not code:
            print(f"{C_RED}[-] 2FA verification cancelled.{C_RESET}")
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
                    print(f"{C_GREEN}{C_BOLD}[+] 2FA verification successful!{C_RESET}")
                    return True
                elif ec == -21669:
                    print(f"{C_RED}[-] Incorrect 2FA verification code (-21669). Please try again!{C_RESET}")
                    continue
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                parsed = plistlib.loads(ensure_plist_wrapper(body))
                ec = parsed.get("Response", {}).get("Status", {}).get("ec", 0)
                if ec == 0:
                    print(f"{C_GREEN}{C_BOLD}[+] 2FA verification successful!{C_RESET}")
                    return True
                elif ec == -21669:
                    print(f"{C_RED}[-] Incorrect 2FA verification code (-21669). Please try again!{C_RESET}")
                    continue
            except Exception:
                pass
            print(f"{C_RED}[-] Verification error (HTTP {e.code}).{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[-] 2FA connection error: {e}{C_RESET}")

    return False


# =============================================================================
#   SRP-6A LOGIN AUTHENTICATION WORKFLOW
# =============================================================================

def perform_srp_login(username: str, password: str, profile: dict, depth: int = 0) -> dict:
    """Execute complete GrandSlam SRP-6a login workflow"""
    if depth > 0:
        print(f"\n{C_CYAN}[*] Continuing authentication after 2FA (attempt {depth})...{C_RESET}")
    else:
        print(f"\n{C_BOLD}{C_BLUE}[*] Starting Apple ID authentication: {username}{C_RESET}")
        print(f"[*] Client-Info profile: {profile['name']}")

    # 1. Fetch Anisette headers
    print("[*] Connecting to fetch Anisette headers...")
    ani, ani_url = fetch_anisette()
    print(f"{C_GREEN}[+] Anisette connection successful: {ani_url}{C_RESET}")

    client_info = profile["client_info"]
    ua = profile["user_agent"]
    svct = profile["svct"]

    # 2. Generate SRP public key pair A
    # a: 256 bits random number (32 bytes)
    a_bytes = secrets.token_bytes(32)
    a = int.from_bytes(a_bytes, byteorder="big")
    A = pow(g, a, N)
    A_bytes = pad_to_n(A)

    # 3. Send Init Request (o = "init")
    print("[*] [1/3] Sending SRP Init handshake to gsa.apple.com...")
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
        raise RuntimeError(f"GSA Init failed (ec={ec}): {em}")

    protocol = init_resp.get("sp", "s2k")
    salt = extract_bytes(init_resp.get("s"))
    b_pub_bytes = extract_bytes(init_resp.get("B"))
    c_challenge = init_resp.get("c")
    iterations = int(init_resp.get("i", 20000))

    if not salt or not b_pub_bytes or not c_challenge:
        raise RuntimeError(f"Init response missing required data (s={bool(salt)}, B={bool(b_pub_bytes)}, c={bool(c_challenge)})")

    print(f"{C_GREEN}[+] SRP Init successful (protocol={protocol}, iterations={iterations}, salt_len={len(salt)}){C_RESET}")

    # 4. Calculate SRP Challenge Response
    print("[*] Calculating PBKDF2 & SRP proof (M1)...")
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

    # 5. Send Complete Request (o = "complete")
    print("[*] [2/3] Sending SRP Complete proof to gsa.apple.com...")
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

    # Verify M2 proof from server
    if "M2" in complete_resp:
        m2_server = extract_bytes(complete_resp.get("M2"))
        expected_m2 = hashlib.sha256(a_natural + m1 + session_key).digest()
        if m2_server == expected_m2:
            print(f"{C_GREEN}[+] Server proof M2 verified successfully!{C_RESET}")
        else:
            print(f"{C_YELLOW}[!] Server proof M2 mismatch.{C_RESET}")

    # Decrypt SPD payload if present
    spd_dict = {}
    if "spd" in complete_resp:
        spd_raw = extract_bytes(complete_resp.get("spd"))
        if spd_raw and HAS_CRYPTOGRAPHY:
            try:
                decrypted_spd = decrypt_cbc(session_key, spd_raw)
                wrapped_spd = ensure_plist_wrapper(decrypted_spd)
                spd_dict = plistlib.loads(wrapped_spd)
                print(f"{C_GREEN}[+] Successfully decrypted SPD payload ({len(spd_dict)} keys).{C_RESET}")
            except Exception as e:
                print(f"{C_YELLOW}[!] SPD payload decryption failed: {e}{C_RESET}")
                if 'decrypted_spd' in locals():
                    print(f"  [DEBUG-SPD] First 100 bytes: {decrypted_spd[:100]}")

    hsc = comp_status.get("hsc", 200)
    spd_status = spd_dict.get("status-code")
    spd_authmode = spd_dict.get("authmode")

    # Multi-layer extraction of au: Status -> Response -> SPD (au) -> SPD (authmode)
    auth_type = (
        comp_status.get("au")
        or complete_resp.get("au")
        or spd_dict.get("au")
        or (spd_authmode if spd_authmode != "password" else None)
    )

    if not auth_type and (hsc == 409 or spd_status == 409):
        auth_type = spd_authmode or "trustedDeviceSecondaryAuth"

    # Check for authentication error
    if comp_ec != 0 and not auth_type:
        em = comp_status.get("em", "Invalid Apple ID or password")
        raise RuntimeError(f"Authentication failed (ec={comp_ec}): {em}")

    # 6. Handle 2FA verification if required
    if auth_type and any(k in str(auth_type) for k in ("SecondaryAuth", "secondaryAuth", "trustedDeviceSecondaryAuth", "smsSecondaryAuth")):
        print(f"\n{C_MAGENTA}{C_BOLD}[!] Apple requires 2FA verification: {auth_type}{C_RESET}")
        dsid = (
            to_string(spd_dict.get("adsid"))
            or to_string(spd_dict.get("dsid"))
            or to_string(comp_status.get("dsid"))
            or to_string(complete_resp.get("dsid"))
        )
        idms_token = (
            to_string(spd_dict.get("GsIdmsToken"))
            or to_string(spd_dict.get("idmsToken"))
            or to_string(comp_status.get("idmsToken"))
            or to_string(complete_resp.get("idmsToken"))
        )

        if not dsid or not idms_token:
            raise RuntimeError("Missing DSID or IDMS-Token for 2FA verification!")

        already_sent = (hsc == 409 or spd_status == 409)
        if not already_sent:
            time.sleep(2)

        twofa_ok = handle_trusted_device_2fa(ani, client_info, dsid, idms_token, already_sent=already_sent)
        if not twofa_ok:
            raise RuntimeError("2FA verification failed.")

        if depth >= 1:
            print(f"{C_YELLOW}[*] 2FA verification completed.{C_RESET}")
        else:
            print(f"{C_CYAN}[*] 2FA OK! Automatically reconnecting in 2s to retrieve session tokens...{C_RESET}")
            time.sleep(2)
            return perform_srp_login(username, password, profile, depth=depth + 1)

    # 7. Extract session tokens
    adsid = (
        to_string(spd_dict.get("adsid"))
        or to_string(spd_dict.get("dsid"))
        or to_string(comp_status.get("dsid"))
    )
    idms_token = (
        to_string(spd_dict.get("GsIdmsToken"))
        or to_string(spd_dict.get("idmsToken"))
    )
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

    # 8. Request Xcode AppToken (com.apple.gs.xcode.auth)
    if adsid and c_resp and idms_token and sk and HAS_CRYPTOGRAPHY:
        print("\n[*] [3/3] Requesting Xcode AppToken (com.apple.gs.xcode.auth)...")
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

            # If Apple prompts 2FA (-22411) specifically at the AppToken stage
            if token_ec == -22411:
                print(f"\n{C_MAGENTA}{C_BOLD}[2FA] 📱 Apple sent a 2FA verification code (-22411) to your Apple device!{C_RESET}")
                code = input(f"{C_BOLD}{C_YELLOW}[?] Enter 6-digit code shown on iPhone/iPad: {C_RESET}").strip()
                if code:
                    print("[2FA] Submitting verification code to Apple...")
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
                                print(f"{C_GREEN}[+] 2FA verification successful! Fetching AppToken...{C_RESET}")
                                time.sleep(2)
                                token_resp = gsa_request(app_params, client_info, ani, ua, svct=svct, retries=1)
                    except Exception as ve:
                        print(f"{C_RED}[-] 2FA verification failed: {ve}{C_RESET}")

            et = extract_bytes(token_resp.get("et"))
            if et:
                decrypted_et = decrypt_gcm(sk, et)
                wrapped_et = ensure_plist_wrapper(decrypted_et)
                et_plist = plistlib.loads(wrapped_et)
                token_val = et_plist.get("t", {}).get(APP_XCODE_AUTH, {}).get("token")
                if token_val:
                    print(f"{C_GREEN}{C_BOLD}[+] Received Xcode AppToken successfully!{C_RESET}")
                    auth_result["app_token"] = token_val
                    test_developer_api(adsid, token_val, ani)
        except Exception as e:
            print(f"{C_YELLOW}[!] Error requesting AppToken: {e}{C_RESET}")

    return auth_result


def test_developer_api(adsid: str, app_token: str, ani: dict):
    """Test Apple Developer Services API (listTeams) using the retrieved AppToken"""
    print(f"\n{C_BOLD}{C_BLUE}[*] Verifying Apple Developer API access (listTeams)...{C_RESET}")
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
                print(f"{C_GREEN}{C_BOLD}[+] Apple Developer Services API connection SUCCESSFUL!{C_RESET}")
                print(f"  • Teams found: {len(teams)}")
                for t in teams:
                    t_name = t.get("name", "N/A")
                    t_id = t.get("teamId", "N/A")
                    t_type = t.get("type", "Individual")
                    print(f"    - [{t_id}] {t_name} ({t_type})")
                return teams
            else:
                user_str = parsed.get("userString") or parsed.get("resultString", f"resultCode: {rc}")
                print(f"{C_YELLOW}[!] Apple Developer API response (rc={rc}): {user_str}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}[-] Apple Developer API error: {e}{C_RESET}")
    return None


# =============================================================================
#   PROBE CLIENT-INFO WORKFLOW
# =============================================================================

def run_probe():
    """Run automated probe for all Client-Info and Services candidate pairs"""
    print("=" * 80)
    print(f"{C_BOLD}{C_GREEN}  🍎 APPLE GRANDSLAM GSA - CLIENT-INFO & SERVICES PROBER{C_RESET}")
    print("=" * 80)
    print("[*] Connecting to fetch Anisette headers...")
    try:
        ani, server = fetch_anisette()
        print(f"{C_GREEN}[*] Successfully connected to server: {server}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}[-] Anisette error: {e}{C_RESET}")
        return

    print(f"[*] Anisette Device-ID: {ani.get('X-Mme-Device-Id', '')[:18]}...")
    print(f"[*] Total candidates to test: {len(PROBE_CANDIDATES)}")
    print("-" * 80)

    results = []
    for idx, (name, ci, ua, svct) in enumerate(PROBE_CANDIDATES, 1):
        sys.stdout.write(f"[{idx:02d}/{len(PROBE_CANDIDATES):02d}] {name:<45} ... ")
        sys.stdout.flush()

        user_id = str(uuid.uuid4()).upper()
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
                print(f"{C_RED}❌ BLOCKED (ec=-80045){C_RESET}")
                results.append((name, ci, ua, svct, False, -80045, em))
            elif ec == -20101:
                print(f"{C_GREEN}✅ OK (ec=-20101){C_RESET}")
                results.append((name, ci, ua, svct, True, -20101, em))
            else:
                print(f"{C_YELLOW}⚠️  EC={ec}{C_RESET}")
                results.append((name, ci, ua, svct, False, ec, em))
        except urllib.error.HTTPError as e:
            print(f"{C_RED}❌ BLOCKED (ec={e.code}){C_RESET}")
            results.append((name, ci, ua, svct, False, e.code, str(e)))
        except Exception as e:
            print(f"{C_RED}❌ ERROR ({e}){C_RESET}")
            results.append((name, ci, ua, svct, False, -1, str(e)))

        time.sleep(0.3)

    print("=" * 80)
    passed = [r for r in results if r[4]]
    failed = [r for r in results if not r[4]]
    print(f"{C_BOLD}  RESULTS: {C_GREEN}{len(passed)} ACCEPTED{C_RESET} | {C_RED}{len(failed)} BLOCKED{C_RESET}")
    print("=" * 80)


# =============================================================================
#   MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Apple GSA Client-Info Prober & GrandSlam SRP Login Tool")
    parser.add_argument("--probe", action="store_true", help="Run Client-Info compatibility probe")
    parser.add_argument("--login", action="store_true", help="Authenticate Apple ID account")
    parser.add_argument("-u", "--username", help="Apple ID (Email)")
    parser.add_argument("-p", "--password", help="Apple ID Password")
    parser.add_argument("-c", "--client", default="pixel7_akd", help="Client-Info profile (pixel7_akd, iphone16_akd, pixel8, iphone16_dev)")
    parser.add_argument("-o", "--output", help="Save authenticated session to JSON file")

    args = parser.parse_args()

    # Select client profile
    selected_profile = next((p for p in CLIENT_PROFILES if p["id"] == args.client), CLIENT_PROFILES[0])

    if args.probe:
        run_probe()
        return

    if args.login:
        username = args.username or input(f"{C_BOLD}[?] Enter Apple ID (Email): {C_RESET}").strip()
        password = args.password or getpass.getpass(f"{C_BOLD}[?] Enter Apple ID Password: {C_RESET}")
        if not username or not password:
            print(f"{C_RED}[-] Apple ID and Password cannot be empty!{C_RESET}")
            return
        try:
            res = perform_srp_login(username, password, selected_profile)
            print("\n" + "=" * 80)
            print(f"{C_GREEN}{C_BOLD}🎉 LOGIN SUCCESSFUL! AUTHENTICATED SESSION:{C_RESET}")
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
            print(f"{C_GREEN}[+] Session saved to: {out_file}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}{C_BOLD}❌ LOGIN FAILED: {e}{C_RESET}")
        return

    # Interactive menu if run without arguments
    print("=" * 80)
    print(f"{C_BOLD}{C_GREEN}  🍎 FORTIVA - APPLE GRANDSLAM GSA TOOLKIT{C_RESET}")
    print("=" * 80)
    print("  [1] Probe Client-Info & Services Compatibility (Probe Mode - No password required)")
    print("  [2] Full Apple ID Login (GrandSlam SRP + 2FA + AppToken)")
    print("  [0] Exit")
    print("-" * 80)

    choice = input(f"{C_BOLD}Select option [1/2/0]: {C_RESET}").strip()
    if choice == "1":
        run_probe()
    elif choice == "2":
        print(f"\n{C_BOLD}Select Client-Info profile:{C_RESET}")
        for idx, p in enumerate(CLIENT_PROFILES, 1):
            print(f"  [{idx}] {p['name']}")
        p_choice = input(f"Select profile [1-{len(CLIENT_PROFILES)}] (default 1): ").strip()
        try:
            p_idx = int(p_choice) - 1
            if 0 <= p_idx < len(CLIENT_PROFILES):
                selected_profile = CLIENT_PROFILES[p_idx]
        except Exception:
            selected_profile = CLIENT_PROFILES[0]

        username = input(f"\n{C_BOLD}[?] Enter Apple ID (Email): {C_RESET}").strip()
        password = getpass.getpass(f"{C_BOLD}[?] Enter Apple ID Password: {C_RESET}")
        if not username or not password:
            print(f"{C_RED}[-] Apple ID and Password cannot be empty!{C_RESET}")
            return
        try:
            res = perform_srp_login(username, password, selected_profile)
            print("\n" + "=" * 80)
            print(f"{C_GREEN}{C_BOLD}🎉 LOGIN SUCCESSFUL! AUTHENTICATED SESSION:{C_RESET}")
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
            print(f"{C_GREEN}[+] Session saved to: {out_file}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}{C_BOLD}❌ LOGIN FAILED: {e}{C_RESET}")
    else:
        print("Goodbye!")

if __name__ == "__main__":
    main()
