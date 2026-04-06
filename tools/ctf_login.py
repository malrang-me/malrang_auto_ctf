#!/usr/bin/env python3
"""
CTF Platform Login Helper
==========================
Logs into CTF platforms via headed browser (shows the window).
Saves session cookies to ~/.ctf-browser-state.json for headless reuse.

Usage:
  python3 tools/ctf_login.py                    # Interactive: pick platform
  python3 tools/ctf_login.py dreamhack          # Direct platform login
  python3 tools/ctf_login.py https://ctf.example.com  # Custom URL login

After login, all subsequent Playwright MCP sessions will be auto-logged-in.
"""

import sys
import os
import json
from playwright.sync_api import sync_playwright

STATE_FILE = os.path.expanduser("~/.ctf-browser-state.json")

PLATFORMS = {
    "dreamhack": {
        "name": "Dreamhack",
        "login_url": "https://dreamhack.io/login",
        "check_url": "https://dreamhack.io",
        "logged_in_selector": "a[href='/mypage']",
    },
    "cryptohack": {
        "name": "CryptoHack",
        "login_url": "https://cryptohack.org/login/",
        "check_url": "https://cryptohack.org",
        "logged_in_selector": "a[href='/user/']",
    },
    "picoctf": {
        "name": "picoCTF",
        "login_url": "https://play.picoctf.org/login",
        "check_url": "https://play.picoctf.org",
        "logged_in_selector": ".avatar",
    },
    "htb": {
        "name": "HackTheBox",
        "login_url": "https://app.hackthebox.com/login",
        "check_url": "https://app.hackthebox.com",
        "logged_in_selector": ".user-menu",
    },
}

def merge_state(existing_path, new_cookies):
    """Merge new cookies into existing state file without losing other platform cookies."""
    existing = {"cookies": [], "origins": []}
    if os.path.exists(existing_path):
        try:
            with open(existing_path, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    # Get domains of new cookies
    new_domains = set()
    for c in new_cookies:
        new_domains.add(c.get("domain", ""))

    # Remove old cookies for these domains, keep others
    merged = [c for c in existing.get("cookies", [])
              if c.get("domain", "") not in new_domains]
    merged.extend(new_cookies)

    existing["cookies"] = merged
    return existing


def login_platform(platform_key=None, custom_url=None):
    """Open headed browser for login. Save cookies on close."""

    if custom_url:
        login_url = custom_url
        platform_name = custom_url
    elif platform_key and platform_key in PLATFORMS:
        p = PLATFORMS[platform_key]
        login_url = p["login_url"]
        platform_name = p["name"]
    else:
        print("Available platforms:")
        for key, p in PLATFORMS.items():
            print(f"  {key:12s} — {p['name']:20s} ({p['login_url']})")
        print(f"  {'custom':12s} — Enter any URL")
        print()
        choice = input("Select platform (or URL): ").strip()
        if choice in PLATFORMS:
            return login_platform(choice)
        elif choice.startswith("http"):
            return login_platform(custom_url=choice)
        else:
            print(f"Unknown platform: {choice}")
            return

    print(f"\nOpening {platform_name} login page...")
    print("Log in manually in the browser window.")
    print("When done, close the browser window or press Ctrl+C.\n")

    # Load existing state (pass file path to Playwright, which reads the JSON)
    existing_state = STATE_FILE if os.path.exists(STATE_FILE) else None

    with sync_playwright() as pw:
        # HEADED browser so user can see and interact
        browser = pw.chromium.launch(headless=False)
        context = browser.new_context(
            storage_state=existing_state if os.path.exists(STATE_FILE) else None
        )
        page = context.new_page()
        page.goto(login_url, timeout=30000)

        print(f"Browser opened at {login_url}")
        print("Please log in. The browser will stay open until you close it.")

        try:
            # Wait for browser to close (user closes it after logging in)
            page.wait_for_event("close", timeout=300000)  # 5 min max
        except:
            pass

        # Save cookies
        try:
            state = context.storage_state()
            merged = merge_state(STATE_FILE, state.get("cookies", []))
            with open(STATE_FILE, "w") as f:
                json.dump(merged, f, indent=2)

            cookie_count = len(merged["cookies"])
            print(f"\nSaved {cookie_count} cookies to {STATE_FILE}")
            print("All future headless sessions will be auto-logged-in.")
        except Exception as e:
            print(f"\nWarning: could not save state: {e}")
        finally:
            try:
                context.close()
                browser.close()
            except:
                pass


def check_login(platform_key):
    """Check if already logged in to a platform."""
    if platform_key not in PLATFORMS:
        return False

    p = PLATFORMS[platform_key]
    if not os.path.exists(STATE_FILE):
        return False

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(storage_state=STATE_FILE)
        page = context.new_page()
        page.goto(p["check_url"], timeout=15000)

        try:
            page.wait_for_selector(p["logged_in_selector"], timeout=5000)
            logged_in = True
        except:
            logged_in = False

        context.close()
        browser.close()
        return logged_in


def status():
    """Check login status for all platforms."""
    print("CTF Platform Login Status")
    print("=" * 50)
    for key, p in PLATFORMS.items():
        try:
            logged_in = check_login(key)
            status = "LOGGED IN" if logged_in else "not logged in"
        except:
            status = "error checking"
        print(f"  {p['name']:20s} {status}")
    print()
    print(f"State file: {STATE_FILE}")
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            state = json.load(f)
        print(f"Total saved cookies: {len(state.get('cookies', []))}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        login_platform()
    elif sys.argv[1] == "status":
        status()
    elif sys.argv[1] == "all":
        for key in PLATFORMS:
            login_platform(key)
    elif sys.argv[1].startswith("http"):
        login_platform(custom_url=sys.argv[1])
    else:
        login_platform(sys.argv[1])
