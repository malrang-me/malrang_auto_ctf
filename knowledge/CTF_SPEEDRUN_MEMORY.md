# CTF Speedrun Memory

Purpose: keep short, high-signal lessons that make future solves faster.

## How To Use
- Before solving: skim this file and apply matching patterns first.
- After solving: append one new entry with evidence-backed notes.
- Keep each entry focused on speed and reproducibility.

## Entry Template
- Challenge: <name>
- Category: <crypto/pwn/web/reversing/web3>
- Date: <YYYY-MM-DD>
- Fast Detection Signals:
  - <signal 1>
  - <signal 2>
- Winning Chain:
  - <short chain>
  - Why it won: <reason>
- Failure Signatures -> Immediate Fix:
  - <signature> -> <fix>
- Reusable Assets:
  - <script/snippet/checklist>ㅣㅣㅣㅣㅣㅣㅣㅣㅣ
- Expected Speed-up Next Time:
  - <estimate>

---

## Entry 001 - Perfect RSA
- Challenge: Perfect RSA
- Category: crypto
- Date: 2026-03-01
- Fast Detection Signals:
  - `getPrime` was patched to use Python `random.randbytes` (MT19937), not CSPRNG.
  - Option1 leaked structured `(DEBUG count, Generated prime)` data repeatedly.
  - 4000-query cap strongly suggested full-state/near-full-state recovery path.
- Winning Chain:
  - Build GF(2) symbolic MT model from option1 leaks -> derive affine state -> use option2 `cp` + divisibility check on `N` to resolve residual DOF and recover `p`.
  - Why it won: all decisions were deterministic and log-verifiable; only small residual search remained.
- Failure Signatures -> Immediate Fix:
  - `dof` occasionally > threshold on remote (`29~30`) -> auto-retry full run until favorable DOF (`<=28`).
  - Slow remote interactions -> pipeline input (`"1\n" * queries + "2\n"`) to remove RTT bottleneck.
  - Wrong MT bit equations / shift semantics -> enforce logical shift model and verify with local end-to-end.
- Reusable Assets:
  - `codex_crypto/Perfect_RSA/solve.py` (pipelined mode by default)
  - `codex_crypto/Perfect_RSA/retry_remote.py` (automated retry with per-attempt logs)
  - Artifacts to check first:
    - `artifacts/remote_retry_summary.log`
    - `artifacts/run_remote_attempt_*.log`
- Expected Speed-up Next Time:
  - 2x to 4x faster time-to-first-flag for similar MT-leak RSA challenges.

---

## Entry 002 - Arena Workflow (Squid-style Adaptation)
- Challenge: workflow-upgrade
- Category: all
- Date: 2026-03-01
- Fast Detection Signals:
  - 20+ minutes with no meaningful score increase.
  - Same failure signature repeated 3 times.
  - Three candidate chains blocked by the same bottleneck.
- Winning Chain:
  - Split into role-based branches (Scout/Builder/Breaker/Judge), run A/B/C in 10-minute rounds, kill lowest branch each round, mutate from top branch assumptions.
  - Why it won: reduced single-chain tunnel vision and made branch selection evidence-driven.
- Failure Signatures -> Immediate Fix:
  - Branch logs missing comparable metrics -> enforce scoreboard format before next round.
  - Too many branch ideas with no execution -> require one reproducible evidence item per branch per round.
  - False positives survived too long -> keep dedicated Breaker branch active every round.
- Reusable Assets:
  - `scripts/init_agent_arena.ps1`
  - `artifacts/HYPOTHESIS_POOL.md`
  - `artifacts/BRANCH_SCOREBOARD.md`
  - `artifacts/DECISION_LOG.md`
- Expected Speed-up Next Time:
  - 1.5x to 3x faster convergence on hard challenges with multiple plausible chains.

---

## Entry 003 - Dynamic Recon Prompting
- Challenge: pipeline-upgrade
- Category: all
- Date: 2026-03-01
- Fast Detection Signals:
  - Generic prompt keeps exploring broad space without committing.
  - Solver fails for avoidable parser/format reasons early.
- Winning Chain:
  - Run recon first, then auto-generate challenge-specific `DYNAMIC_SOLVER_PROMPT.md`, and only then execute solver phase.
  - Why it won: reduced irrelevant branches and front-loaded parser/model pitfalls specific to the target.
- Failure Signatures -> Immediate Fix:
  - Recon output too generic -> force explicit chain ranking + first 30-min plan in dynamic prompt.
  - Solver ignored recon output -> inject dynamic prompt block as top-priority context.
  - KB stale/no-hit -> append writeup/paper/1-day query queue to `RESEARCH_QUEUE.md`.
- Reusable Assets:
  - `scripts/codex_run.ps1` (two-stage mode)
  - `artifacts/RECON_REPORT.md`
  - `artifacts/DYNAMIC_SOLVER_PROMPT.md`
  - `artifacts/RESEARCH_QUEUE.md`
- Expected Speed-up Next Time:
  - 1.5x to 2.5x faster time-to-first-working-chain on unfamiliar challenge families.

---

## Entry 004 - Team-Lead File Bus
- Challenge: pipeline-upgrade-v2
- Category: all
- Date: 2026-03-01
- Fast Detection Signals:
  - Solver context drifts between attempts.
  - Good findings are lost when branch switches happen.
- Winning Chain:
  - Use file-based teammate bus (`memory/*.md` + `artifacts/RUNNER_QUEUE.md` + `artifacts/TEAM_EVENTS.md`) so recon/solver/runner/critic handoffs are explicit.
  - Why it won: orchestration survives long sessions and restarts, and branch decisions remain auditable.
- Failure Signatures -> Immediate Fix:
  - Branch decisions undocumented -> require TEAM_EVENTS update before branch kill/promote.
  - Runnable candidate path unclear -> enforce `EXPLOIT_READY` format in RUNNER_QUEUE.
  - Same failure rediscovered -> append to `memory/failures.md` with signature key.
- Reusable Assets:
  - `scripts/codex_run.ps1`
  - `scripts/solve_pipeline.ps1`
  - `templates/_common/memory/*.md`
  - `templates/_common/artifacts/RUNNER_QUEUE.md`
  - `templates/_common/artifacts/TEAM_EVENTS.md`
- Expected Speed-up Next Time:
  - 1.3x to 2x faster retries on hard, multi-branch challenges.

---

## Entry 005 - Wow FSB
- Challenge: Wow FSB
- Category: pwn
- Date: 2026-03-06
- Fast Detection Signals:
  - Input gate rejects when `%` appears 2 or more times; single-specifier payloads are mandatory.
  - Loop exit depends on global `total == 0xdeadbeefdeadbeef`.
  - Stable PIE/libc/env leaks exist at `%78$p`, `%51$p`, `%72$p`; stable injected-pointer slot exists at `%42$...`.
- Winning Chain:
  - Leak PIE/libc/env, compute `saved_rip_slot = environ - 0x130`, then use `%42$hhn` to place a 4-qword `ret -> pop rdi -> cmd -> system` chain and finally force `main` to return via `total`.
  - Why it won: it turns the loop into a deterministic ret2system without needing FSOP or pointer-mangling recovery.
- Failure Signatures -> Immediate Fix:
  - WSL launch denied in sandbox -> rerun command with escalated permission.
  - Host pwntools cache permission error -> run solver in WSL Python environment.
  - Inline shell quoting breaks probes -> move probes into standalone script files.
  - `%hhn` write unexpectedly trips `No Hack~ ^_^` -> check destination-address bytes for `0x25` and retry on a new ASLR layout or choose a shorter/safer range.
- Reusable Assets:
  - `codex_pwn/와! FSB/solve.py`
  - `codex_pwn/와! FSB/probe_offsets.py`
  - `codex_pwn/와! FSB/probe_stable.py`
  - `codex_pwn/와! FSB/probe_argpos.py`
  - `codex_pwn/와! FSB/probe_libc_ret.py`
  - `codex_pwn/와! FSB/probe_stack_rel.py`
- Expected Speed-up Next Time:
  - 3x to 5x faster on single-specifier FSB loops that expose both libc and stack leaks.
- Refinement Notes (2026-03-07):
  - Check `%50$p` and `%1$p` before committing to `environ`; if either gives a stable frame/buffer anchor, derive the saved return slot directly.
  - Prefer a libc `"/bin/sh"` chain over a PIE-side command string when the libc base is already known; it cuts write count and bad-byte exposure.
  - Do not lock onto one injected-pointer slot too early; low-40s slots such as `%40$hhn`, `%41$hhn`, and `%42$hhn` can all be valid depending on the exact stack layout.

---

## Entry 006 - singlerand
- Challenge: singlerand
- Category: crypto
- Date: 2026-03-08
- Fast Detection Signals:
  - `sum(r.getrandbits(32) for _ in range(396)) == 0` means every sampled word must be zero.
  - CPython `random.Random(int_seed)` uses `init_by_array` and hard-forces `state[0] = 0x80000000`.
  - The packaged runtime is Python 3.14.3, so decimal seed length is part of exploitability because of `int_max_str_digits`.
- Winning Chain:
  - Construct the minimal pre-twist state with `state[0] = 0x80000000`, `state[397] = 0x40000000`, others `0`, then invert both `init_by_array` loops to recover a valid seed.
  - Why it won: it turned the branch into a deterministic state-construction problem with clean local verification.
- Failure Signatures -> Immediate Fix:
  - `ValueError: Exceeds the limit (4300 digits)` -> run local verification with `PYTHONINTMAXSTRDIGITS=0` and record the runtime caveat.
  - Reduced `key_length = 397` BV model stalls -> stop burning time on stock Z3 and switch to a stronger BV backend or a word-level recurrence derivation.
- Reusable Assets:
  - `codex_crypto/singlerand/solve.py`
  - `codex_crypto/singlerand/artifacts/solve_run.log`
  - `codex_crypto/singlerand/WRITEUP_NOTION.md`
- Expected Speed-up Next Time:
  - 2x to 3x faster on MT challenges where the success predicate is a zero-prefix or other simple post-twist state pattern.

## Entry 007 - Not So Smart
- Challenge: Not So Smart
- Category: crypto
- Date: 2026-03-29
- Fast Detection Signals:
  - Challenge name hints at "Smart's attack"
  - ECC problem with custom curve parameters
  - Description: "what's wrong with this curve" = anomalous curve
- Winning Chain:
  - Verify #E(GF(p)) == p (anomalous) → Smart's attack via p-adic lifting → recover private key m → compute shared_secret → AES-CBC decrypt
  - Why it won: single well-known attack, pure Python implementation works without SageMath
- Failure Signatures -> Immediate Fix:
  - SageMath not installed → use pure Python p-adic arithmetic implementation
  - Hensel lift fails → ensure lifted point satisfies curve equation mod p^2
- Reusable Assets:
  - `challenges/Not_So_Smart/solve.py` (Smart's attack, pure Python)
- Expected Speed-up Next Time:
  - 5x+ faster — reuse solve.py template for any anomalous curve challenge

---

## Entry 008 - 이것도 딸깍해 보시지!
- Challenge: 이것도 딸깍해 보시지!
- Category: misc
- Date: 2026-03-29
- Fast Detection Signals:
  - PDF 파일에 Python 코드가 있고 실행 결과를 서버에 제출하는 형태
  - 문제 이름/이미지가 AI 사용을 풍자 ("딸깍" = AI에 복붙)
  - 댓글에 "징벌 당했다", "복붙했습니다 반성" 등 함정 힌트
- Winning Chain:
  - PDF를 이미지로 렌더링 → 실제 연산자/들여쓰기 확인 → 정확한 코드 실행 → nc 제출
  - Why it won: 텍스트 추출 대신 이미지 확인으로 함정 회피
- Failure Signatures -> Immediate Fix:
  - pdftotext/get_text()로 추출한 코드가 틀림 -> PDF를 이미지로 렌더링해서 확인
  - 하나의 if-elif 체인으로 해석 -> 들여쓰기 확인, 별도 if 블록 여부 체크
  - `>=` vs `>`, `<=` vs `<` 연산자 혼동 -> 이미지에서 정확히 읽기
- Reusable Assets:
  - pymupdf로 PDF→이미지 변환: `page.get_pixmap(dpi=200).save("out.png")`
- Expected Speed-up Next Time:
  - 10x+ — PDF 코드 문제 = 무조건 이미지 렌더링 먼저

---

## Entry 009 - Times
- Challenge: Times
- Category: reversing
- Date: 2026-03-29
- Fast Detection Signals:
  - .init_array에 `time(0)` 비교 → 미래 날짜 시간 게이트
  - .init_array에 `ptrace(PTRACE_TRACEME)` + 전역 u16 XOR 패턴
  - main에서 동일한 `time(0)` 호출로 seed를 두 번 생성 → 키스트림 XOR 두 번 적용
  - 32비트 비트 반전 루프가 유일한 비가역 변환처럼 보임
- Winning Chain:
  - ptrace 결과 추적 → 일반 실행 시 전역 XOR 키가 0x0000 → 16-bit XOR 단계 항등
  - 동일 time() seed → 동일 MD5 키스트림 → 두 XOR 패스 상쇄
  - 남은 변환 = bit_reverse_32 (자기 역함수)
  - 목표 데이터에 bit_reverse_32 적용 → 등록 키 즉시 획득
  - Why it won: 보호 메커니즘 분석으로 실질 변환을 하나로 줄인 후 역산이 자명해짐
- Failure Signatures -> Immediate Fix:
  - 시간 게이트로 바이너리 실행 불가 -> `LD_PRELOAD` faketime.so로 `time()`을 임계값+1로 패치
  - 디버거에서 잘못된 XOR 키 관찰 -> 디버거 없이 실행, ptrace 결과 재확인
  - 키스트림 XOR 취소를 놓침 -> seed 생성 코드가 완전히 동일한지 정적 분석으로 확인
- Reusable Assets:
  - `challenges/Times/solve.py` (bit_reverse_32 + 목표 데이터 → 키 복원)
  - faketime.c 패턴: `time_t time(time_t *t) { time_t v = TARGET; if(t)*t=v; return v; }`
  - XOR 취소 패턴 인식: 동일 seed를 두 번 쓰는 XOR 구조는 항등 → 무시하고 나머지 분석
- Expected Speed-up Next Time:
  - 5x+ — 시간 게이트 + ptrace 조합은 단골 패턴. LD_PRELOAD 우회 즉시 적용 가능

---

## Entry 010 - playing-with-login
- Challenge: playing-with-login
- Category: web
- Date: 2026-03-29
- Fast Detection Signals:
  - v1/v2 두 버전 공존 (마이그레이션 패턴)
  - MariaDB 11.3+ 사용 (docker-compose에서 `mariadb:11.3.x` 확인)
  - v2 엔드포인트가 `abort(501)` 반환하지만 DB 쿼리가 먼저 실행됨
  - username이 form input 그대로 inbox key로 사용 vs DB 조회 결과 사용
- Winning Chain:
  - v1 signup "ádmin" → v2 request-pw "ádmin" (DB accent-insensitive match) → v1 login → mypage에서 토큰 획득 → v2 change-pw → v2 login admin → flag
  - Why it won: MariaDB 11.3의 uca1400_ai_ci collation이 accent-insensitive라는 점과, abort 전 side-effect를 정확히 파악
- Failure Signatures -> Immediate Fix:
  - MariaDB 버전별 기본 collation 모름 -> docker-compose에서 이미지 버전 확인, 11.3+는 uca1400_ai_ci
  - accent 문자로 가입 시 "already exists" -> collation이 accent-sensitive일 수 있음, case만 다른 문자로 시도 (단 v1 signup은 .lower() 적용)
- Reusable Assets:
  - `challenges/playing-with-login/solve.py`
  - MariaDB collation 체크: `SELECT @@collation_database;`
  - accent 문자 목록: á(U+00E1), à(U+00E0), ä(U+00E4), â(U+00E2)
- Expected Speed-up Next Time:
  - 5x+ — v1/v2 공존 + MariaDB 11.3+ 패턴 즉시 인식 가능

---

## Entry - Magnus_Carlsen
- Challenge: Magnus_Carlsen
- Category: pwn
- Date: 2026-03-21
- Fast Detection Signals:
  - <fill me>
- Winning Chain:
  - <fill me>
  - Why it won: <fill me>
- Failure Signatures -> Immediate Fix:
  - <signature> -> <fix>
- Reusable Assets:
  - <script/snippet/checklist>
- Expected Speed-up Next Time:
  - <fill me>

---

## Entry 011 - Basic_CrackME
- Challenge: Basic_CrackME
- Category: reversing
- Date: 2026-03-30
- Fast Detection Signals:
  - AutoIt compiled script (.exe) with embedded x86 shellcode
  - 32-character input validated character-by-character
  - CRC32 computation inside shellcode (polynomial 0xEDB88320)
  - Hardcoded FLAG array XORed with a key
- Winning Chain:
  - Decompile AutoIt -> extract shellcode -> identify standard CRC32
  - Brute-force XOR key 0~255: count positions that map to printable ASCII
  - Key 0x7F (127) gives 32/32 matches -> DH{Profitez_des_analyses_AUTOIT}
  - Why it won: 256-iteration brute is instant, avoids trusting stated key value
- Failure Signatures -> Immediate Fix:
  - Used stated key 0xDEADC0DE directly -> no printable result
  - Fix: AutoIt truncates large integers to byte -> stated key != effective key -> always brute 0~255
- Reusable Assets:
  - CRC32 reverse lookup: brute all printable ASCII, build crc->char map
  - XOR key brute-force with printability scoring (count valid ASCII / total)
  - challenges/Basic_CrackME/solve.py
- Expected Speed-up Next Time:
  - AutoIt + CRC32 + XOR pattern recognized in <5 min -> flag in ~10 min

---

## Entry 012 - 1-Weight Overwrite
- Challenge: 1-Weight Overwrite
- Category: ai
- Date: 2026-03-30
- Fast Detection Signals:
  - MNIST model with high accuracy (99%+)
  - "Modify exactly ONE weight" = adversarial weight perturbation
  - TanhLinear final layer (bounded effective weights via tanh * scale)
  - 100 rounds with increasing difficulty: banned layers + shrinking value ranges
- Winning Chain:
  - Gradient-guided search: backprop d(logit[target]-logit[predicted])/dw → rank candidates by gradient*(extreme-current) → verify top-300 with forward pass → first that flips argmax wins
  - Why it won: gradient is a strong signal for which weight matters most; early conv/DSC layers have cascading effects through BatchNorm/ReLU that amplify single-weight changes
- Failure Signatures -> Immediate Fix:
  - fc2 TanhLinear layer alone insufficient for high-confidence predictions -> search ALL layers via gradient
  - Analytical fc2-only approach predicted wrong argmax -> must verify ALL 10 logits, not just target vs predicted
  - Banned layers use glob patterns (e.g., `fc2.*`) -> use fnmatch, not exact string match
  - Server timeout on brute-force -> gradient search is O(backward + 300 forward) ≈ 0.3s, well within limits
- Reusable Assets:
  - `challenges/1-Weight_Overwrite/solve.py` (gradient-guided single-weight adversarial attack)
  - Key pattern: gradient * (extreme_value - current_value) as ranking heuristic for large discrete changes
  - Early conv layers (dsc1.dw.conv especially) give outsized impact due to cascading through BN/ReLU
- Expected Speed-up Next Time:
  - 10x+ — gradient-guided single-weight attack template directly reusable for any "modify K weights" challenge

---

## Entry 013 - baby-turbofan (학습 기반)
- Challenge: baby-turbofan
- Category: pwn (V8 Browser Exploitation)
- Date: 2026-03-31
- Source: GoN 2022 Spring Open Qual / Dreamhack #462
- Fast Detection Signals:
  - V8 d8 바이너리 + patch 파일 제공
  - TurboFan / JIT 관련 키워드 (turbofan, typer, optimization)
  - Math.expm1 또는 유사한 수학 함수 타입 버그 패치 revert
  - "Krautflare" 언급 → 동일 계열 버그
- Winning Chain:
  - `Object.is(Math.expm1(x), {mz:-0}.mz)` → escape analysis + 잘못된 타입 추론 → bounds check 제거 → OOB
  - OOB로 인접 BigUint64Array length 조작 → 영구 OOB
  - Heap base leak (pointer compression 상위 32bit) → addrof primitive
  - ArrayBuffer backing_store 덮어쓰기 → AAR/AAW
  - WASM 인스턴스 RWX 페이지 → shellcode 쓰기 → 실행
  - Why it won: V8 exploit 표준 체인. 모든 primitive가 OOB 하나에서 파생
- Failure Signatures -> Immediate Fix:
  - Krautflare exploit 그대로 사용 → pointer compression 때문에 실패 → 오프셋 동적 디버깅 필수
  - OOB 인덱스 계산 틀림 → `%DebugPrint` + GDB로 힙 레이아웃 확인
  - WASM RWX 오프셋 틀림 → `addrof(wasmInstance) + offset`은 V8 버전마다 다름, GDB 확인
  - JIT 최적화 안 됨 → 100000회 "0" 문자열 호출로 deopt feedback 충분히 축적
- Reusable Assets:
  - `knowledge/techniques/v8_turbofan_exploitation.md` (전체 체인 + 코드)
  - `knowledge/challenges/baby-turbofan.md` (전체 exploit 코드)
  - itof/ftoi 변환 함수 템플릿
  - WASM minimal module 바이트코드 (42를 반환하는 최소 모듈)
  - x86-64 execve("/bin/sh") shellcode: `\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05`
- Expected Speed-up Next Time:
  - 5x+ — V8 TurboFan 타입 혼동 문제는 동일 체인 적용. 오프셋만 GDB로 확인하면 됨

---

## Entry 014 - GoN 2022 Collection (15문제 일괄 학습)
- Challenge: 2022 Spring GoN Open Qual (A~V)
- Category: multi (crypto/pwn/rev/web/misc/blockchain)
- Date: 2026-03-31
- Source: https://g0riya.github.io/posts/2022-Spring-GoN-Open-Qual-Writeup/

### 고속 패턴 모음

**Crypto 패턴**:
- `% 0xff` vs `& 0xFF` → 값 255 누락 → 통계적 공격 (CS448)
- AES-CTR + 같은 IV → null 암호화로 keystream leak → XOR 복호화 (Interchange)
- Legendre PRF → cryptolu/LegendrePRF 레포 직접 사용 (Legendary)

**Pwn 패턴**:
- Rust 바이너리 + unsafe heap → 전통적 glibc tcache 공격 적용 가능 (Oxidized)
- `scanf("%Ns")` 버퍼와 N이 같으면 null byte off-by-one → SFP 조작 (NullNull)
- `__free_hook` 주소에 0x80+ 바이트 → UTF-8 검증 크래시 → ASLR 재시도 (Oxidized)

**Reversing 패턴**:
- 복잡한 연산 + 작은 입력 공간 → GDB Python 브루트포스 (`set $rip`로 반복) (Nonsense)
- 커스텀 블록 암호 (ARIA sbox + AES shift) → 역연산 구현 + C++ 포팅 (Unconventional)
- pyc XOR 난독화 → 키 XOR → 수동 opcode 해석 → 역연산 (pyc)
- Zero-run 비트 인코딩 → 1 카운트 = 비트 수, 리틀엔디안 디코딩 (RUN)

**Web 패턴**:
- JS 백엔드 + 사용자 입력이 객체 키 → `__proto__` prototype pollution (NSS)
- report 기능 + CSS injection → CSRF → 내부 엔드포인트 접근 (ColorfulMemo)
- LFI + SQLi `INTO OUTFILE` → 웹쉘 → RCE (ColorfulMemo)
- prototype pollution으로 `base_dir` 오염 → 임의 파일 읽기 (NSS)

**Misc 패턴**:
- SHA512 블록 비교 → 타이밍 사이드채널 (Leetcode)
- OTF 폰트 GSUB 리가처 체인 역추적 → TTX로 XML 변환 후 분석 (input box)

**Blockchain 패턴**:
- 컨트랙트 스토리지 = 블록체인 탐색기에서 직접 읽기 가능 (billionaire)

### Failure → Fix
- Python 0xC0FF33회 반복 너무 느림 → C++ 포팅 (Unconventional)
- 자동 타이밍 임계값 어려움 → 수동 확인 병행 (Leetcode)
- UTF-8 검증이 heap addr 크래시 → ASLR 재시도로 valid UTF-8 주소 대기 (Oxidized)

### 출제자 라이트업 추가 패턴 (2026-03-31)

**Pwn 고급 패턴**:
- Rust `unsafe { Box::from_raw(...) }` + drop 없이 벡터 유지 → UAF (Oxidized)
- `scanf("%Ns")` null off-by-one → SFP → one_gadget (`0xe3b31`) + ASLR 루프 (NullNull)

**Reversing 고급 패턴**:
- 복잡한 해시 리버싱 대신 ctypes로 바이너리 함수 직접 호출 브루트포스 (Nonsense)
  - `cdll.LoadLibrary('./main')` + `CFUNCTYPE`으로 0x10000개 매핑 → GDB보다 10배 빠름
- `xchg rsp, rax` 커스텀 호출규약 → RSP↔RAX 스왑 후 디컴파일 (Unconventional)

**Web 고급 패턴**:
- TLS Session ID poisoning + DNS rebinding → Memcached SSRF → pickle RCE (Albireo, 3 solves)
- pickle custom Unpickler 우회: `__dict__` → `__builtins__` → `eval` 체인 (Pieces, 2 solves)
- 모듈 체인 탐색: `mod.submod.six.sys.modules["os"]` (Pieces)

**Redis 패턴**:
- 32-bit BITFIELD 정수 오버플로우 → ~512MB OOB → type confusion → GOT overwrite (Rendezvous, 0 solves)
- `DEBUG mallctl arena.0.extent_hooks` → jemalloc 훅 조작 → 최신 Redis RCE (Mirai, 0 solves)
- 기존: SLAVEOF + MODULE LOAD, CONFIG SET dir/dbfilename (crontab/ssh/webshell)

### Reusable Assets
- `knowledge/challenges/GoN2022_collection.md` (전체 라이트업 + 출제자 보강)
- `knowledge/techniques/prototype_pollution.md`
- `knowledge/techniques/timing_attack.md`
- `knowledge/techniques/gdb_scripting.md`
- `knowledge/techniques/web_exploit_chains.md`
- `knowledge/techniques/v8_turbofan_exploitation.md`
- `knowledge/techniques/ssrf_tls_session_poisoning.md`
- `knowledge/techniques/pickle_deserialization.md`
- `knowledge/techniques/redis_exploitation.md`

---

## Entry 015 - GoN 2022 Fall Collection (5문제 출제자 라이트업)
- Challenge: 2022 Fall GoN Open Qual (F~J)
- Category: web, pwn
- Date: 2026-03-31
- Source: https://hackmd.io/@Xion/goq_22f_authors_writeup

### 고속 패턴 모음

**Web 패턴**:
- Express.js stat/stream 분리 + `/proc` → TOCTOU race → fd 재사용으로 환경변수 leak (Heliodor, 2 solves)
- Django `dictsort` stable sort → CVE-2021-45116 사이드채널 → Z3로 UUID 복원 (Emerald Tablet, 7 solves)

**Pwn 고급 패턴**:
- TLS 배열 오버플로우 → TCB dtv 포인터 조작 → `_dl_resize_dtv()` realloc → fake chunk → tcache overlap (Reconquista, 0 solves)
- Redis XAUTOCLAIM count 정수 오버플로우 (CVE-2022-35951) → heap overflow → 객체 위조 → RCE (Redis-made, 0 solves)
- QEMU DMA MMIO reentrancy → UAF → safe-linking 디코딩 → TCG RWX tcache poisoning → VM escape (NPU, 1 solve)

### 핵심 기법 인사이트

**CVE 패치 분석 → 파생 취약점** (Redis-made):
- CVE-2022-31144 패치의 같은 코드 영역에서 CVE-2022-35951 발견
- CTF 출제 단골 패턴: 패치된 CVE 주변에 미패치 취약점 존재

**QEMU TCG RWX 주소 계산** (NPU):
```c
rwx = (heap_base & ~0xffffffULL) + 0xc000000;  // heap 근처 고정 오프셋
```

**Safe-linking 디코딩** (glibc 2.32+):
```c
// encoded = (real_addr >> 12) ^ next_ptr
// 상위 비트부터 순차적으로 복원
heap |= encoded & (0xfff << 36);
heap |= (encoded ^ (heap >> 12)) & (0xfff << 24);
heap |= (encoded ^ (heap >> 12)) & (0xfff << 12);
heap |= (encoded ^ (heap >> 12)) & 0xfff;
```

**Chained Recursive MMIO** (NPU):
- DMA 버퍼 주소를 MMIO 물리 주소로 설정 → 단일 요청으로 여러 MMIO 연산 실행
- free + leak + alloc을 하나의 RWvec 요청으로 원자적 수행

### Reusable Assets
- `knowledge/challenges/GoN2022F_collection.md` (전체 라이트업 + 전체 exploit 코드)
- `knowledge/techniques/qemu_vm_escape.md`
- `knowledge/techniques/tls_dtv_exploitation.md`
- `knowledge/techniques/race_condition_toctou.md`
- `knowledge/techniques/redis_exploitation.md` (CVE-2022-35951 추가)

---

## Entry 016 - RBG+++ & lance-hard? (학습 기반)
- Challenge: RBG+++ (KalmarCTF 2026) + lance-hard? (KalmarCTF 2025)
- Category: crypto
- Date: 2026-04-01
- Source: Sceleri writeup + Neobeo writeup
- Fast Detection Signals:
  - `m^e + m^{f(e)} mod N` 형태 (지수에 LCG/선형 관계)
  - N이 작은 소수 곱 (인수분해 가능)
  - 다수의 (e, r) 쌍 + 지수 간 대수적 관계
  - 타원곡선 x좌표 합 (lance-hard? 변형)
- Winning Chain:
  - N 인수분해 → 변수 치환으로 monic `x³+x≡r·z` → LLL로 지수 관계식 (k=8, ±4) → 대수적 수 이론 (companion matrix + Newton's identities) → Fast Lagrange interpolation → 두 다항식 GCD → z 복원 → m 복원
  - Why it won: resultant 대신 대수적 수 기법으로 O(mn) 계수 계산, 연속점 보간으로 O(n)
- Failure Signatures -> Immediate Fix:
  - 직접 resultant → 차수 2^28 폭발 → 양수/음수 분리 + 대수적 수 기법
  - `gcd(f, z^p-z)` 단일 다항식 → NTL FFT 한계 → 두 다항식 GCD로 우회
  - non-monic 다항식 → 변수 치환 `e+(1337-N)/2`로 monic화
- Reusable Assets:
  - `knowledge/challenges/rbg_plus_plus_plus.md`
  - `knowledge/techniques/lll_algebraic_number_poly.md`
  - lance-hard? 패턴: Wagner's Birthday (±1계수 12개) → Semaev S₁₂ → Fast Lagrange → gcd(f, x^p-x)
- Expected Speed-up Next Time:
  - 유사 구조 인식 → 즉시 수식 변환 + LLL 파라미터 선택 가능 (분석 시간 -2h)
  - 대수적 수 기법 코드 재사용 (구현 시간 -3h)
  - 총 계산은 여전히 ~10h 필요 (본질적으로 heavy)
