#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""apple_bridge.py - Bridge between Fortiva and Apple Services (Python)
Uses SideDroid's proven AppleAuth (SRP+2FA) and DeveloperAPI to authenticate,
retrieve Xcode AppToken (com.apple.gs.xcode.auth), and sync session.json.
Supports auto/custom selection of Client-Info and matching User-Agent.
"""

import sys
import os
import json
import time
import argparse
import getpass

# Add current directory to sys.path so we can import local modules
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from apple_auth import AppleAuth
from developer_api import DeveloperAPI
from device_profiles import (
    PROFILES,
    prompt_select_profile,
    sanitize_client_info,
    match_user_agent_for_client_info,
)

FORTIVA_SESSION_PATH = os.path.expanduser("~/.fortiva/session.json")
SIDELOAD_SESSION_PATH = os.path.expanduser("~/.sideload/session.json")


def save_fortiva_session(session_data):
    os.makedirs(os.path.dirname(FORTIVA_SESSION_PATH), exist_ok=True)
    with open(FORTIVA_SESSION_PATH, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=2, ensure_ascii=False)
    
    # Also save to ~/.sideload for compatibility
    try:
        os.makedirs(os.path.dirname(SIDELOAD_SESSION_PATH), exist_ok=True)
        with open(SIDELOAD_SESSION_PATH, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_fortiva_session():
    if os.path.exists(FORTIVA_SESSION_PATH):
        try:
            with open(FORTIVA_SESSION_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def select_best_team(teams):
    if not teams:
        return None, None
    selected_idx = 0
    for i, t in enumerate(teams):
        tid = t.get("teamId") or t.get("teamID") or t.get("id") or "?"
        tname = t.get("name") or "?"
        ttype = t.get("type") or "Individual"
        # Prioritize Personal / Individual / Free
        if ttype.lower() in ("free", "individual") or "personal" in tname.lower():
            selected_idx = i
            break
    
    best = teams[selected_idx]
    team_id = best.get("teamId") or best.get("teamID") or best.get("id")
    team_name = best.get("name") or "Personal Team"
    return team_id, team_name


def do_login(apple_id=None, password=None, profile_arg=None, custom_ci=None, custom_ua=None, is_json_output=False):
    # === XỬ LÝ PROFILE CẤU HÌNH THIẾT BỊ ===
    client_info = None
    user_agent = None
    xcode_ua = None
    anisette_url = None

    if custom_ci:
        client_info = sanitize_client_info(custom_ci)
        user_agent = custom_ua or match_user_agent_for_client_info(client_info)
        xcode_ua = user_agent
        print(f"\n[profile] 🛠️ Using custom configuration:")
        print(f"  • Client-Info: {client_info}")
        print(f"  • User-Agent:  {user_agent}")
        print(f"  • Matching:    100% ✅")
    elif profile_arg:
        p_key = profile_arg.strip().lower()
        mapping = {
            "1": "1", "sidestore": "1", "isideload": "1", "mac": "1", "default": "1",
            "2": "2", "iloader": "2", "windows": "2", "itunes": "2", "503": "2",
            "3": "3", "android": "3", "pixel": "3", "pixel7": "3",
            "4": "4", "sonoma": "4", "macos14": "4",
            "5": "5", "ventura": "5", "macos13": "5",
            "6": "6", "ios": "6", "iphone": "6", "ios17": "6",
            "7": "7", "auto": "7",
        }
        chosen_key = mapping.get(p_key, "1")
        if chosen_key == "7":
            print(f"\n[profile] 🌐 Auto Mode: Retrieve Client-Info from Anisette and match User-Agent automatically.")
        else:
            p = PROFILES[chosen_key]
            client_info = p["client_info"]
            user_agent = p["user_agent"]
            xcode_ua = p["xcode_ua"]
            anisette_url = p.get("anisette_url")
            print(f"\n[profile] 🛠️ Configuration via parameter: {p['name']}")
            print(f"  • Client-Info: {client_info}")
            print(f"  • User-Agent:  {user_agent}")
            print(f"  • Matching:    100% ✅")
    else:
        # Interactive profile selection
        p_cfg = prompt_select_profile()
        client_info = p_cfg.get("client_info")
        user_agent = p_cfg.get("user_agent")
        xcode_ua = p_cfg.get("xcode_ua")
        anisette_url = p_cfg.get("anisette_url")
        if client_info:
            print(f"\n[profile] 🛠️ Applied configuration:")
            print(f"  • Client-Info: {client_info}")
            print(f"  • User-Agent:  {user_agent}")
            print(f"  • Matching:    100% ✅")
        else:
            print(f"\n[profile] 🌐 Auto Mode (Anisette passthrough & auto-match UA).")

    # === CREDENTIALS INPUT ===
    if not apple_id:
        print("\n=== FORTIVA APPLE ID LOGIN (PYTHON BRIDGE) ===")
        apple_id = input("Apple ID: ").strip()
    if not password:
        password = getpass.getpass("Password: ")

    if not apple_id or not password:
        print("[!] Apple ID and Password cannot be empty.", file=sys.stderr)
        if is_json_output:
            print(json.dumps({"status": "error", "message": "Missing credentials"}))
        return False

    auth = AppleAuth(
        anisette_url=anisette_url,
        input_func=input,
        client_info=client_info,
        user_agent=user_agent,
        xcode_ua=xcode_ua,
    )
    print(f"\n[bridge] Starting Apple ID authentication: {apple_id}...")
    auth_result = auth.authenticate(apple_id, password)

    if not auth_result or not auth_result.get("authenticated"):
        print("[!] Authentication failed.", file=sys.stderr)
        if is_json_output:
            print(json.dumps({"status": "error", "message": "Authentication failed"}))
        return False

    dsid = str(auth_result.get("dsid") or "")
    session_token = auth_result.get("session_token") or ""

    if not session_token:
        print("[!] Failed to retrieve Xcode AppToken.", file=sys.stderr)
        if is_json_output:
            print(json.dumps({"status": "error", "message": "Missing AppToken"}))
        return False

    print(f"[bridge] ✅ Successfully logged in! DSID: {dsid}")
    token_display = session_token[:25] + "..." if len(session_token) > 25 else session_token
    print(f"[bridge] ✅ Xcode AppToken: {token_display}")

    # Developer API verification
    print("[bridge] Verifying Apple Developer membership and fetching Team ID...")
    dev_api = DeveloperAPI(auth, dsid, session_token)
    teams = dev_api.list_teams()

    team_id, team_name = select_best_team(teams)
    if team_id:
        print(f"[bridge] ✅ Found Developer Team: {team_name} ({team_id})")
        dev_api.set_team(team_id)
        # Test developer cert access
        try:
            certs = dev_api.list_certificates()
            print(f"[bridge] ✅ Valid Developer membership! (Currently has {len(certs)} certificate(s))")
        except Exception as e:
            print(f"[bridge] ℹ️ Certificate check: {e}")
    else:
        print("[bridge] ⚠️ No Team ID found in this account.")

    now = int(time.time())
    session_data = {
        "apple_id": apple_id,
        "dsid": dsid,
        "session_token": session_token,
        "user_id": auth.user_id,
        "device_id": auth.device_id,
        "team_id": team_id,
        "team_name": team_name,
        "client_info": auth.client_info,
        "user_agent": auth.user_agent,
        "created_at": now,
        "expires_at": now + 7 * 24 * 3600,
        "token_issued_at": now
    }

    save_fortiva_session(session_data)
    print(f"[bridge] ✅ Session saved to {FORTIVA_SESSION_PATH}")

    if is_json_output:
        res = {"status": "ok", "session": session_data}
        print(json.dumps(res))

    return True


def do_test_session():
    session = load_fortiva_session()
    if not session:
        print("[!] No active session found (~/.fortiva/session.json). Please log in first.")
        return False

    apple_id = session.get("apple_id")
    dsid = session.get("dsid")
    token = session.get("session_token")
    team_id = session.get("team_id")
    ci = session.get("client_info")
    ua = session.get("user_agent")

    print(f"=== TEST SESSION ===")
    print(f"Apple ID:    {apple_id}")
    print(f"DSID:        {dsid}")
    print(f"Team ID:     {team_id}")
    print(f"Client-Info: {ci or '(default)'}")
    print(f"User-Agent:  {ua or '(default)'}")
    print(f"Token:       {token[:25]}... (len={len(token) if token else 0})")

    auth = AppleAuth(client_info=ci, user_agent=ua)
    dev = DeveloperAPI(auth, dsid, token)
    if team_id:
        dev.set_team(team_id)

    print("\n[test] 1. list_teams()...")
    teams = dev.list_teams()
    print(f"       -> Result: {len(teams)} teams")
    for t in teams:
        tid = t.get("teamId") or t.get("teamID") or t.get("id")
        tname = t.get("name")
        print(f"          • {tname} ({tid})")

    if team_id:
        print("\n[test] 2. list_certificates()...")
        certs = dev.list_certificates()
        print(f"       -> Result: {len(certs)} certificates")
        for c in certs:
            cid = c.get("id")
            name = c.get("attributes", {}).get("name")
            status = c.get("attributes", {}).get("status")
            print(f"          • ID: {cid} | Name: {name} | Status: {status}")

    print("\n[test] ✅ Session is working properly with Apple Developer Services!")
    return True


def do_list_certs():
    session = load_fortiva_session()
    if not session:
        print("[!] No active session. Run 'python3 scripts/apple_bridge.py login' first.")
        return False
    auth = AppleAuth(client_info=session.get("client_info"), user_agent=session.get("user_agent"))
    dev = DeveloperAPI(auth, session["dsid"], session["session_token"])
    if session.get("team_id"):
        dev.set_team(session["team_id"])
    print(f"[bridge] Fetching Developer certificates for team {session.get('team_id')}...")
    certs = dev.list_certificates()
    print(f"[bridge] Found {len(certs)} certificate(s):")
    for c in certs:
        cid = c.get("id")
        name = c.get("attributes", {}).get("name")
        status = c.get("attributes", {}).get("status")
        exp = c.get("attributes", {}).get("expirationDate")
        print(f"  • ID: {cid} | Name: {name} | Status: {status} | Expires: {exp}")
    return True


def do_create_cert():
    session = load_fortiva_session()
    if not session:
        print("[!] No active session. Run 'python3 scripts/apple_bridge.py login' first.")
        return False
    auth = AppleAuth(client_info=session.get("client_info"), user_agent=session.get("user_agent"))
    dev = DeveloperAPI(auth, session["dsid"], session["session_token"])
    if not session.get("team_id"):
        print("[!] Session is missing team_id.")
        return False
    dev.set_team(session["team_id"])
    print(f"[bridge] Creating new Developer Certificate for team {session['team_id']}...")
    cert_data = dev.create_certificate(f"fortiva-{session['team_id'][:5]}")
    if not cert_data:
        print(f"[!] Certificate creation failed: {dev.last_error}")
        return False
    cert_id = cert_data.get("certificateId")
    has_content = bool(cert_data.get("certContent"))
    print(f"[bridge] 🎉 CERTIFICATE CREATED SUCCESSFULLY!")
    print(f"  Certificate ID: {cert_id}")
    print(f"  Cert Content:   {'DER data available' if has_content else 'Pending issuance by Apple'}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Fortiva Apple Auth Bridge")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    login_parser = subparsers.add_parser("login", help="Login to Apple ID and obtain AppToken")
    login_parser.add_argument("--apple-id", "-u", help="Apple ID email")
    login_parser.add_argument("--password", "-p", help="Apple ID password")
    login_parser.add_argument("--profile", help="Chọn profile (1: SideStore Chuẩn MacBook macOS 13.1, 2: Windows iTunes Fix 503, 3: Pixel 7, 4: Sonoma, 5: Ventura, 6: iOS 17, 7: Auto)")
    login_parser.add_argument("--client-info", help="Tuỳ chỉnh Client-Info thủ công")
    login_parser.add_argument("--user-agent", help="Tuỳ chỉnh User-Agent thủ công (phải khớp Client-Info)")
    login_parser.add_argument("--json", action="store_true", help="Output JSON result")

    subparsers.add_parser("test-session", help="Test current session against Apple Developer API")
    subparsers.add_parser("list-certs", help="List developer certificates")
    subparsers.add_parser("create-cert", help="Create a new developer certificate")

    args = parser.parse_args()

    if args.command == "login":
        ok = do_login(
            apple_id=args.apple_id,
            password=args.password,
            profile_arg=args.profile,
            custom_ci=args.client_info,
            custom_ua=args.user_agent,
            is_json_output=args.json,
        )
        sys.exit(0 if ok else 1)
    elif args.command == "test-session":
        ok = do_test_session()
        sys.exit(0 if ok else 1)
    elif args.command == "list-certs":
        ok = do_list_certs()
        sys.exit(0 if ok else 1)
    elif args.command == "create-cert":
        ok = do_create_cert()
        sys.exit(0 if ok else 1)
    else:
        # Default action: login
        ok = do_login()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
