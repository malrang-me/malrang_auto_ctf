# Multi-Platform Auto-Intake

## Supported Platforms
| Platform | URL Pattern | Login Method |
|---|---|---|
| Dreamhack | `dreamhack.io/wargame/challenges/*` | ID/PW or OAuth |
| CTFd-based | `*/challenges` | ID/PW |
| picoCTF | `play.picoctf.org` | ID/PW |
| CryptoHack | `cryptohack.org` | ID/PW |
| HackTheBox | `app.hackthebox.com` | ID/PW |
| Generic | any URL | manual |

## 병렬 세션 충돌 방지 (CRITICAL)

**Chrome MCP는 하나뿐** — 여러 세션이 동시에 브라우저를 쓰면 충돌한다.

### 인테이크 잠금 프로토콜
인테이크(브라우저 사용) 전에 반드시 잠금 파일 확인:
```bash
# 잠금 확인
if [ -f .intake_lock ]; then
    echo "[intake] 다른 세션이 인테이크 중. 완료될 때까지 대기..."
    while [ -f .intake_lock ]; do sleep 3; done
fi

# 잠금 획득
echo "$CHALLENGE_NAME $(date +%s)" > .intake_lock

# ... 인테이크 수행 (브라우저 사용) ...

# 잠금 해제
rm -f .intake_lock
```

### 규칙
- **인테이크 시작 전** `.intake_lock` 파일 확인 → 있으면 대기
- **인테이크 완료 후** 즉시 `.intake_lock` 삭제
- 잠금 30초 이상 유지되면 stale로 간주하고 강제 해제
- 인테이크 끝나면 브라우저 놔두고 **풀이는 브라우저 없이 진행** (병렬 OK)

### curl/WebFetch 우선 (브라우저 DOM 스냅샷은 ~9k 토큰 낭비)

**브라우저 DOM 스냅샷(read_page 등)은 인테이크 토큰의 60%+ 를 차지함. 최대한 피할 것.**

#### Dreamhack
```bash
# 챌린지 정보 읽기 (WebFetch — DOM 스냅샷보다 10x 저렴)
WebFetch url="https://dreamhack.io/wargame/challenges/XXX" prompt="카테고리, 설명, 첨부파일 URL, remote host:port 추출"

# 첨부파일 다운로드 (curl — 토큰 0)
curl -sL -o challenges/<name>/file.zip "https://dreamhack.io/api/..."
```

#### CTFd 계열
```bash
WebFetch url="<challenge_url>" prompt="파일 다운로드 URL, 설명, 카테고리 추출"
curl -sL -o file.zip "<download_url>"
```

#### 일반 규칙
1. **WebFetch 먼저** — 페이지 내용 읽기 (토큰 ~1k)
2. **curl로 파일 다운로드** — 토큰 0
3. **Chrome MCP는 최후 수단** — 로그인 필요하거나 JS 렌더링 필수일 때만
4. **read_page / DOM 스냅샷 금지** — 인테이크에서 사용하면 안 됨

## Browser Environment
- **Windows Claude App**: Chrome MCP (`mcp__Claude_in_Chrome__*`)
- **WSL Claude Code**: Playwright MCP (`mcp__playwright__*`, headless)
  - Config: `.mcp.wsl.json`
  - 각 세션이 headless 인스턴스를 따로 띄우므로 **WSL에서는 충돌 없음**

## Persistent Login
Browser sessions persisted in `~/.ctf-browser-data/`.
- **NEVER store passwords in files**

## Intake Procedure
1. 사용자 입력 파악: URL? 파일 경로? 문제 이름?
2. **curl 다운로드 시도** (직접 링크면 브라우저 불필요)
3. curl 실패 시 → `.intake_lock` 확인 → 잠금 획득 → 브라우저 사용
4. 챌린지 페이지 읽기: category, description, attachments, host/port
5. 첨부파일 다운로드 → `challenges/<name>/` 에 배치
6. **`.intake_lock` 즉시 해제** (브라우저 사용 끝)
7. Scaffold: `python tools/ops.py scaffold <name> --category <cat>`
8. `triage.py` 실행 (터미널 제목 자동 변경)
9. Write `meta.yaml` with remote info
10. Init checkpoint
11. Start solving (브라우저 없이 — 병렬 안전)

## Edge Cases
- Login required: 브라우저로 로그인 → 쿠키 저장 → 다음부터 curl+cookie 가능
- Multiple attachments: download all to same folder
- Existing folder: append timestamp suffix
- No attachments (remote only): record host:port in meta.yaml
