# CLAUDE.md — malrang_auto_ctf v3 (token-optimized)

Autonomous CTF solving framework. BASE = `C:\Users\malrangme\Desktop\malrang_auto_ctf`

## Distributed Rules
Shared rules live in `.claude/rules/`:
- **`common.md`** — failure classification, library preference, tool routing, causal chain, handoff, checkpoint, verification, computation offload
- **`reporting.md`** — 성과 보고서 포맷 (reporter only)
- **`learning.md`** — 학습 트리거, post-flag/failure learning
- **`session.md`** — session architecture, /compact rules, token budget
- **`ctf_pipeline.md`** — pipeline selection, agent model assignment
- **`intake.md`** — multi-platform auto-intake

---

## 1. Goal
- End-to-end: analyze → write solver → execute → verify → report flag.
- Completion = flag recovered + verified + reported for manual submission.
- **NEVER submit flags** to any platform. User submits manually. NO exceptions.

### 실전 모드 (Contest Mode)
사용자가 `--mode contest` 또는 "실전 모드", "대회 모드"라고 하면 활성화.
**속도 최우선. 토큰 절감보다 빠른 풀이가 중요.**
- critic 에이전트: easy/medium에서 **스킵**
- reporter: **flag만 기록**, 보고서는 대회 후 일괄 작성
- dual approach: 실패 즉시 **병렬 2개** 스폰 (2회 대기 안 함)
- effort: 난이도별 (easy=medium, medium=high, hard=max) — practice와 동일
- verifier: 로컬 1회 + 리모트 1회로 축소 (3회 → 2회)
- FLAGS.txt 추가 + learn.py record만 실행, 나머지 생략

## 2. Architecture: Agent Teams
**MANDATORY** for ALL challenges. Spawn via `subagent_type="<role>"`.
**메인 세션에서 직접 풀기 절대 금지.** 반드시 에이전트를 스폰해서 풀 것.
trivial이어도 최소 ctf-solver → reporter (2-agent) 파이프라인 사용.

### Pipeline Selection
```
trivial:            ctf-solver → [orch: report]                                  (1-agent)
crypto (easy RSA):  crypto_prescreen → [성공시] verifier → [orch: report]        (1-2 agent)
crypto (easy):      reverser → crypto-solver → verifier → [orch: report]        (3-agent)
crypto (med/hard):  reverser → crypto-solver → critic → verifier → reporter     (5-agent)
rev (easy/med):     reverser → solver → verifier → [orch: report]               (3-agent)
rev (hard):         reverser → solver → critic → verifier → reporter            (5-agent)
pwn (vuln clear):   reverser → chain → critic → verifier → [orch: report]       (4-agent)
pwn (vuln unclear): reverser → trigger → chain → critic → verifier              (6-agent)
web:                scout → analyst → exploiter → [orch: report]                (3-agent)
```
**[orch: report]** = 오케스트레이터가 직접 FLAGS.txt + learn.py + 보고서 처리. reporter 에이전트 스폰 안 함.
**reporter 에이전트** = hard 난이도 또는 상세 모델/Effort 분석 필요 시에만 스폰.

### Agent Models
| Agent | Model | Agent | Model |
|-------|-------|-------|-------|
| reverser | **sonnet / opus** (난이도별) | scout | sonnet |
| solver | opus (rev 전용) | analyst | sonnet |
| **crypto-solver** | **opus** (crypto 전용) | exploiter | opus |
| chain | opus | reporter | sonnet |
| critic | opus | ctf-solver | sonnet |
| verifier | sonnet | trigger | sonnet |

### 동적 모델 + effort 선택
triage.py가 `difficulty_signals`를 출력하면, **오케스트레이터가 최종 난이도를 판단**한다.
heuristic과 다르게 판단해도 됨 (예: platform level 5인데 heuristic=medium이면 hard로 올려야).

| 난이도 | reverser | solver/chain effort | 기준 |
|--------|----------|-------------------|------|
| easy | sonnet, medium | medium | 단순 패턴, 소스 제공, Level 1-2 |
| medium | sonnet, medium | high | 보호 기법 있음, Level 3-4 |
| **hard** | **opus**, medium | **max** | 커스텀 VM, 난독화, Level 5-6, 커스텀 libc |

오케스트레이터가 `Agent` 스폰 시 `model`, effort를 오버라이드.

### Context Positioning (Lost-in-Middle Prevention)
```
[Lines 1-2] Critical Facts — vuln type, key values, FLAG conditions
[Lines 3-5] Remote info — host:port, platform, interaction limits
[Middle]    Agent definition (auto-loaded)
[End]       HANDOFF detail (full context, failure history)
```

## 3. Core Rules
1. **Challenge folder isolation**: all files in `challenges/<name>/` only.
2. **Reuse before create**: Glob for existing code first.
3. **Evidence required**: No guessed constants. Record in `memory/discoveries.md`.
4. **FLAGS.txt append**: `<challenge_name> - <flag>` format, append only.
5. **Post-flag sequence (MANDATORY — 절대 생략 금지)**:
   flag 확인 즉시 → **오케스트레이터가 단일 호출**:
   ```
   python tools/post_solve.py <name> --flag "<flag>" --category <cat> --difficulty <easy|medium|hard>
   ```
   이 한 번의 호출이 다음을 모두 처리:
   a. `FLAGS.txt`에 `<name> - <flag>` 추가 (멱등 — 같은 줄이면 skip)
   b. `learn.py record` 호출 → kb.db add + speedrun.db rebuild **자동 cascade**
   c. 간소화 보고서 출력 (cascade 상태 + 타임스탬프 포함)

   **reporter 에이전트는 hard 난이도 + 상세 모델/Effort 분석 필요 시에만 스폰.**
   easy/medium은 `post_solve.py` 한 줄로 끝 → **~20k 토큰 절감.**
   실패 기록도 같은 도구: `python tools/post_solve.py <name> --status failed --category <cat> --notes "..."`
6. **Session start**: check `.compact_needed` file → `/compact` if found.
7. **False-positive prevention**: re-run solver once to confirm reproducibility.
8. **Brute-force timebox**: explicit time limit + abort condition. Use `templates/brute_parallel.py`.

## 4. Five-Minute Gate (every challenge start)
1. Connectivity check (if remote)
2. First contact: banner/prompt/I-O format
3. Local execution check
4. `python tools/triage.py challenges/<name>` → category, difficulty, pipeline, knowledge context (also auto-sets terminal title)
5. **NEVER read full SPEEDRUN_MEMORY (67KB)**. Use only `triage.py` output.
6. Write `memory/recon.md` + `memory/strategy.md` (solver-a and solver-b hypotheses)
7. If L4+ difficulty: WebSearch for writeups/papers. Record in `memory/discoveries.md`.

## 5. Dynamic Context Injection (NEW — v3)
Use `triage.py --build-prompt <agent>` for compact agent prompts:
```bash
python tools/triage.py challenges/<name> --build-prompt solver -c crypto
```
This returns a minimal prompt with only relevant category sections, matching SPEEDRUN entries, and knowledge context — NOT full category files.

## 6. Category System
| Category | File | Key MCP Tools |
|----------|------|---------------|
| crypto | `categories/crypto.md` | solver-z3, sage-helper, solver-cryptominisat |
| pwn | `categories/pwn.md` | pwn-local, py-repl |
| web | `categories/web.md` | Chrome MCP, py-repl |
| rev | `categories/rev.md` | pwn-local, solver-z3, solver-pysat |
| web3/forensics/ai/misc | `categories/<cat>.md` | py-repl + category-specific |

WSL for Linux tools: `wsl python3 exploit.py`, `wsl gdb`, `wsl sage`

## 7. Parallel Solving & Dual-Approach
- **solver-a** (orthodox) + **solver-b** (alternative) — different assumption axes
- Both in `memory/strategy.md` before implementation
- **2 failures → auto-trigger**: spawn 2 solver agents in parallel, first success wins
- **3 failures (same L3) → midsolve_search.py** (offline KB first, web only if 0 hits, 4 calls/challenge cap). 직접 WebSearch 금지 — `rules/common.md` 참조
- Cross-solver: check sibling's `memory/discoveries.md` every 5 steps

## 8. Scaffolding & Tools
```bash
python tools/ops.py scaffold <name> --category <cat> [--remote "host port"]
python tools/ops.py run challenges/<name> [--mode remote] [--timeout 120]
python tools/checkpoint.py init challenges/<name> --agent <first_agent>
python tools/handoff.py create --from reverser --to solver ...
python tools/decision_tree.py next --agent crypto --trigger solve_failure
python tools/state.py set --key vuln_type --val "phi_leaked" --src "output.txt"
python tools/post_solve.py <name> --flag "..." --category <cat> --difficulty <d>  # 단일 post-flag entrypoint
python tools/absorb_memories.py absorb            # challenges/*/memory → SPEEDRUN_MEMORY (idempotent)
python tools/knowledge.py sync         # 신규/삭제 MD 자동 reconcile (post_solve 보완용)
python tools/midsolve_search.py cve|software|technique <q> --challenge <name>  # mid-solve 학습 (rules/common.md 참조)
python tools/speedrun_db.py rebuild    # 수동 rebuild (보통 불필요 — search가 mtime drift 자동 감지)
python tools/speedrun_db.py search "crypto rsa" 3  # search SPEEDRUN entries
# --- Tier 1-3 Rev Pipeline Tools ---
python tools/ida_headless.py full <binary> --challenge-dir <dir>  # IDA 1회 덤프 (토큰 -60%+)
python tools/ida_headless.py metadata <binary>         # 함수/imports/strings/xrefs JSON
python tools/ida_headless.py patch <binary> --script p.py -o patched  # IDAPython 패치
python tools/gdb_auto.py detect <binary>              # anti-debug 자동 탐지
python tools/gdb_auto.py bypass <binary> -o bypass.c   # LD_PRELOAD 생성
python tools/gdb_auto.py patch <binary> -o patched     # NOP 패치
python tools/decompile_bytecode.py decompile <file>     # 바이트코드 자동 디컴파일
python tools/auto_extract.py all <challenge_dir> <bin>  # fact 자동 추출 → state.db
python tools/validate_reversal_map.py <challenge_dir>   # reversal_map 스키마 검증
python tools/solve_loop.py run <challenge_dir>          # solve.py 자동 재시도 + decision_tree
```

## 9. MCP Servers (11 total)
pwn-local, solver-z3, py-repl, solver-pysat, sage-helper, solver-cryptominisat, filesystem, github, notion, docker, ida-pro-mcp*
(*IDA MCP: only when IDA running on 127.0.0.1:13337)
Rule: MCP errors that don't block solve → ignore. MCP broken → CLI fallback.

## 10. Intake
See `rules/intake.md`. Quick ref:
- Trigger: "solve <name>", URL, or platform + challenge name
- Browser: Chrome MCP (Windows) / Playwright MCP (WSL)
- Login: cookies in `~/.ctf-browser-data/`. NEVER store passwords.
- Korean categories accepted: 암호학, 시스템 해킹, 웹 해킹, 리버싱, 포렌식
