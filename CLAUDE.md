# CLAUDE.md — malrang_auto_ctf v2

Autonomous CTF solving framework for Claude Code.
BASE = `C:\Users\malrangme\Desktop\malrang_auto_ctf`

---

## 0. 학습 트리거 (최우선)

사용자가 **"[URL] 학습해"** 또는 **"[URL]에 있는거 학습해"** 형태로 입력하면:

1. 크롤 실행:
   ```
   python tools/bulk_learn.py crawl <URL> --max 20
   ```
   GitHub 레포면 자동으로 마크다운 파일 수집.
   여러 URL이면 `--url-file` 사용.

2. `knowledge/writeup_staging/` 의 미처리 JSON 파일을 **순서대로** 읽는다.

3. 각 파일의 `text` 필드에서 아래 항목을 추출한다:
   - `challenge_name`: 문제 이름
   - `category`: crypto/pwn/web/reversing/web3/misc/forensics
   - `fast_detection_signals`: 이 유형을 빠르게 식별하는 신호 2~4개
   - `winning_chain`: 성공한 공격 체인 요약
   - `why_it_won`: 왜 이 체인이 됐는지 한 문장
   - `failure_signatures`: 실패했던 것 → 즉시 수정법
   - `key_technique`: 핵심 기술명 (예: LLL lattice, ret2libc, SSTI)
   - `reusable_snippet`: 재사용 가능한 코드 패턴

4. 추출한 내용으로 `knowledge/CTF_SPEEDRUN_MEMORY.md`에 엔트리 추가.
   형식은 기존 Entry 템플릿과 동일하게.

5. 처리 완료된 파일은 `"processed": true` 로 업데이트.

6. 전체 완료 후 요약 보고: "N개 라이트업에서 M개 엔트리 학습 완료"

**주의**: 라이트업이 CTF 관련 내용이 아니면 건너뛴다.
텍스트가 너무 짧거나(<300자) 내용 없으면 건너뛴다.

---

## 1. Goal

- Every challenge runs end-to-end: analyze -> write solver -> execute -> verify -> report flag.
- "Idea only" is never acceptable. Completion = flag recovered + verified + reported for manual submission.
- The recovered flag MUST be printed clearly in the final report so the user can copy-paste it.

---

## 1.5. Architecture: Agent Teams

**MANDATORY**: Use Agent Teams for all non-trivial challenges. Never solve directly.
Spawn agents via `subagent_type="<role>"` from `.claude/agents/*.md`.

### Pipeline Selection (see `.claude/rules/ctf_pipeline.md` for full detail)

```
trivial (1-3 line bug):  ctf-solver → reporter                              (2-agent)
crypto / reversing:      reverser → solver → critic → verifier → reporter    (5-agent)
pwn (vuln clear):        reverser → chain → critic → verifier → reporter     (5-agent)
pwn (vuln unclear):      reverser → trigger → chain → critic → verifier      (6-agent)
web:                     scout → analyst → exploiter → reporter              (4-agent)
```

### Agent Model Assignment (MANDATORY — no spawn without model)

| Agent | Model | Role |
|-------|-------|------|
| reverser | sonnet | Structure analysis, attack map |
| solver | opus | Constraint solving, inverse computation |
| chain | opus | Pwn exploit chain assembly |
| critic | opus | Adversarial 2-stage review |
| verifier | sonnet | Execution verification |
| reporter | sonnet | Writeup documentation |
| ctf-solver | sonnet | Trivial single-agent fallback |

### Structured Handoff Protocol

All agent transitions MUST use:
```
[HANDOFF from @<agent> to @<next_agent>]
- Finding/Artifact: <filename>
- Confidence: PASS / PARTIAL / FAIL
- Key Result: <1-2 sentence core result>
- Next Action: <specific task for next agent>
- Blockers: <if any, else "None">
[KNOWLEDGE CONTEXT]: <relevant past challenges/techniques from knowledge/>
```

### Checkpoint Protocol

All work agents maintain `<challenge_dir>/checkpoint.json`:
```json
{"agent":"solver","status":"in_progress","phase":2,"completed":["recon"],"in_progress":"z3_formulation","critical_facts":{},"timestamp":"..."}
```
- `status`: `in_progress` | `completed` | `error`
- Agent idle with `status != completed` → **FAKE IDLE** → resume or respawn
- Hook `.claude/hooks/check_completion.sh` auto-detects this

### Context Positioning (Lost-in-Middle Prevention)
```
[Lines 1-2] Critical Facts — vuln type, key values, FLAG conditions
[Lines 3-5] Remote info — host:port, platform, interaction limits
[Middle]    Agent definition (auto-loaded)
[End]       HANDOFF detail (full context, failure history)
```

---

## 2. Core Rules

1. **Challenge folder isolation**: All problem-specific files (solve.py, exploit.py, memory/, artifacts/) go inside `challenges/<name>/` only. Never write challenge files outside the challenge folder.
2. **Reuse before create**: Before creating any file, Glob for existing code/artifacts. Prefer editing over creating.
3. **Evidence required**: No guessed constants, offsets, or formulas. Every key decision must have a code/output/log basis. Record reasoning in `memory/discoveries.md`.
4. **No auto flag submission**: Never submit flags automatically. Default = recover + verify + report. Only submit if the user explicitly asks in the same turn.
4.5. **MANDATORY learning + compact after flag**:
  The INSTANT a real flag (not DH{flag}/DH{testflag}/placeholder) is confirmed:
  1. Write SPEEDRUN_MEMORY entry BEFORE reporting to user:
     ```
     python tools/learn.py record --challenge-dir challenges/<name> --status success --flag "DH{...}" --category <cat>
     ```
     If learn.py fails, manually append to `knowledge/CTF_SPEEDRUN_MEMORY.md`.
  2. Report flag to user.
  3. Run `/compact` immediately after — no exceptions.
  **Solve sequence: flag → learn → report → /compact. Always in this order.**

  Also: at session START, check for `.compact_needed` file in project root:
  ```bash
  [ -f .compact_needed ] && rm .compact_needed && echo "Previous solve needs compact"
  ```
  If found, run `/compact` before doing anything else.
5. **False-positive prevention**: Re-run the solver at least once to confirm the flag is reproducible. For remote challenges, verify the flag came from the actual server, not a local test.
6. **Brute-force timebox**: Any brute-force must have an explicit time limit (10/20/30 min) and abort condition defined before starting.
7. **Final report format**: (1) What was done (2) How it was verified (3) Remaining risks or caveats.

---

## 3. Loop Detection

Track failure signatures. A failure signature = same error class + same approach.

- **3 same-signature failures**: WARNING. You MUST change at least one assumption, parameter, or approach before retrying. Write the change to `memory/failures.md`.
- **5 same-signature failures**: HARD STOP. You MUST switch to a fundamentally different approach. Document all failed attempts and why they failed in `memory/failures.md` before proceeding.
- **Never**: Retry the exact same thing hoping for a different result. If it failed 3 times, it will fail a 4th time.

### Failure Classification (from LuaN1aoAgent Reflector pattern)
On failure, classify as one of:
- **L1 Transient**: Network timeout, tool crash -> retry with same approach
- **L2 Tool-specific**: Wrong tool parameters, syntax error -> adjust params or switch tool
- **L3 Methodology**: Wrong attack vector, misunderstanding the goal -> pivot strategy entirely
- **L4 Reasoning**: Fundamental misunderstanding of the challenge -> re-read challenge, re-analyze from scratch

Same-level failures compound: 3x L2 -> escalate to L3 investigation. 3x L3 -> escalate to L4.

---

## 4. Flag Verification

A flag candidate is valid ONLY if ALL of these are true:

1. It appears in actual solver execution output (stdout/stderr from running solve.py/exploit.py).
2. It matches the expected flag format (e.g., `DH{...}`, `flag{...}`, `CTF{...}`).
3. It is NOT from: `strings` output, placeholder text, comments in source code, local test flag files, or challenge description.
4. For remote challenges: the flag came from the actual target server, not a local binary.

On finding a candidate: re-run the solver once to confirm reproducibility before reporting.

### Anti-Soliloquying (from EnIGMA research)
"Soliloquying" = hallucinating observations without actually running tools. This is the #1 cause of false positives in AI CTF agents.
- NEVER claim you found something without showing the actual tool output that proves it.
- NEVER say "I ran X and got Y" without the actual execution log visible.
- If you think you know the answer, STILL run the solver to verify.

---

## 4.5. Pipeline Modes (from Machine v2)

| Difficulty | Mode | Flow |
|-----------|------|------|
| Easy | **Lightweight** | solver only — analyze + exploit + verify in one session |
| Medium | **Lightweight + escalation** | solver → spawns @critic if stuck 3x |
| Hard | **Full** | reverser → solver → critic → verifier → reporter |

`triage.py` determines difficulty automatically. Override with `--category`.

### Triage-First Flow (MANDATORY before solving)

```bash
python.exe tools/triage.py challenges/<name> [--category crypto]
```

Output: category, difficulty, pipeline mode, knowledge context block.
The knowledge context is injected into the solver agent's prompt.

### Learning Loop (ALWAYS runs — success or failure)

```bash
# After success
python.exe tools/learn.py record --challenge-dir challenges/<name> --status success --flag "DH{...}" --category crypto

# After failure
python.exe tools/learn.py record --challenge-dir challenges/<name> --status failed --category crypto --notes "DLP infeasible"
```

### Decision Tree (when stuck)

```bash
# Get next approach to try
python.exe tools/decision_tree.py next --agent crypto --trigger solve_failure

# Record that an approach was tried (advances to next)
python.exe tools/decision_tree.py record --agent crypto --trigger solve_failure --action-id z3_attempt
```

### State Management (verified constants)

```bash
# Record a verified fact
python.exe tools/state.py set --key vuln_type --val "phi_leaked" --src "server_output.txt" --agent solver

# Read it back
python.exe tools/state.py get --key vuln_type
```

---

## 5. Five-Minute Gate

Execute these steps at the start of EVERY challenge:

1. **Connectivity**: If remote, verify with `nc -zv <host> <port>` or Python socket.
2. **First contact**: Connect once, capture banner/prompt/I-O format.
3. **Local check**: Verify local execution + dependencies.
4. **Classify**: Determine category. Read `categories/<category>.md` for attack patterns.
5. **Speedrun memory**: Read `knowledge/CTF_SPEEDRUN_MEMORY.md` for matching patterns.
6. **Recon**: Write initial analysis to `memory/recon.md`.
7. **Knowledge acquisition** (from KryptoPilot): If the challenge type requires specialized knowledge (lattice crypto, heap exploitation, etc.), use WebSearch to find relevant writeups, papers, or PoCs. Prefer validated libraries/tools over custom code. Record sources in `memory/discoveries.md`.
8. **Strategy**: Define solver-a and solver-b hypotheses in `memory/strategy.md`.

---

## 6. Category System

8 categories supported. On challenge start, load the matching guide:

| Category | File | MCP Tools |
|----------|------|-----------|
| crypto | `categories/crypto.md` | solver-z3, solver-pysat, solver-cryptominisat, sage-helper, py-repl |
| pwn | `categories/pwn.md` | pwn-local, ida-pro-mcp*, py-repl |
| web | `categories/web.md` | Chrome MCP (built-in), py-repl |
| rev | `categories/rev.md` | pwn-local, ida-pro-mcp*, solver-z3, solver-pysat, sage-helper, py-repl |
| web3 | `categories/web3.md` | py-repl, solver-z3 |
| forensics | `categories/forensics.md` | py-repl |
| ai | `categories/ai.md` | py-repl |
| misc | `categories/misc.md` | solver-z3, sage-helper, py-repl |

*ida-pro-mcp: only when IDA Pro is running with RPC on 127.0.0.1:13337. If unavailable, use objdump/readelf/strings.

### WSL Usage
All Linux-native tools (gdb, pwntools, sage, checksec, one_gadget, binwalk, volatility3) run via WSL:
```
wsl python3 exploit.py
wsl gdb -batch -ex "..." ./binary
wsl checksec --file=./binary
```

---

## 7. Causal Reasoning Chain

(From LuaN1aoAgent + CTFAgent research — prevents hallucination and blind guessing)

Every exploit must follow the Evidence -> Hypothesis -> Vulnerability -> Exploit chain:

```
Evidence (actual tool output)           confidence: 0.9
  ↓ SUPPORTS
Hypothesis (inference from evidence)    confidence: 0.5-0.8
  ↓ REVEALS (after verification)
Vulnerability (confirmed attack surface) confidence: 0.8+
  ↓ EXPLOITS
Exploit (executable payload)            confidence: 0.9+
```

Rules:
- **No hypothesis without evidence**: "I think it has SQLi" requires tool output showing injectable parameter.
- **No vulnerability without verified hypothesis**: Must test the hypothesis and document result.
- **No exploit without confirmed vulnerability**: Don't write exploit code based on guesses.
- Record the chain in `memory/discoveries.md` as you progress.

---

## 8. Parallel Solving & Dual-Approach

Two solver branches for non-trivial challenges:

- **solver-a** (orthodox): high-confidence, textbook approach. Leak-based, deterministic, proven technique.
- **solver-b** (alternative): different assumption axis. Bypass, unconventional gadget, or alternative vulnerability.

Rules:
- solver-b MUST NOT duplicate solver-a's first candidate.
- Both hypotheses recorded in `memory/strategy.md` before implementation.
- Use Claude Code's `Agent` tool to run branches in parallel when warranted.
- If one branch succeeds, stop the other.
- If both fail, analyze in `memory/failures.md` and formulate solver-c.

### Dual-Approach Auto-Trigger (after 2 failures)

When solver/chain fails 2x consecutively:
```
Orchestrator spawns 2 agents simultaneously:
  solver-A (subagent_type="solver", approach A) + solver-B (subagent_type="solver", approach B)
  First success adopted, other terminated.
```
After 4 failures: mandatory `WebSearch` for external writeups.

### Cross-Solver Insights (from CTFAgent message bus pattern)
When running parallel solvers via Agent tool:
- Every 5 steps, check sibling solver's `memory/discoveries.md` for new findings.
- Share useful discoveries (leaked addresses, identified vulnerabilities, flag format hints).
- Never duplicate work the other solver already completed.

### Bump on Stuck (from CTFAgent BumpEngine)
When a solver gives up or gets stuck:
1. Read the solver's `memory/failures.md` for what didn't work.
2. Inject sibling solver's verified findings.
3. Restart with a different approach — never the same one.
4. Escalating cooldown: 1st bump immediate, 2nd bump after 30s analysis, 3rd bump after 2min review.

### Critic 2-Stage Review (from Terminator)
Critic agent performs TWO review stages:
1. **Fact-Check**: Verify every address, offset, constant against binary/server output. GDB/tool verification mandatory.
2. **Logic Review**: Trace full exploit chain. Check ASLR handling, payload fit, ROP constraints, mathematical correctness.
- APPROVED requires ALL checks pass. Single failure = REJECTED with specific fix instructions.
- See `.claude/agents/critic.md` for full checklist.

---

## 9. Multi-Platform Auto-Intake

### Supported Platforms
| Platform | URL Pattern | Login Method |
|---|---|---|
| Dreamhack | `dreamhack.io/wargame/challenges/*` | ID/PW or OAuth |
| CTFd-based | `*/challenges` | ID/PW |
| picoCTF | `play.picoctf.org` | ID/PW |
| CryptoHack | `cryptohack.org` | ID/PW |
| HackTheBox | `app.hackthebox.com` | ID/PW |
| Generic | any URL | manual |

### Trigger
User says "solve <problem_name>", provides a URL, or names a platform + challenge.

### Browser Environment
- **Windows Claude App**: Chrome MCP (`mcp__Claude_in_Chrome__*`)
- **WSL Claude Code**: Playwright MCP (`mcp__playwright__*`, headless)
  - Config: `.mcp.wsl.json` with `--user-data-dir ~/.ctf-browser-data`
  - Launch: `claude --mcp-config .mcp.wsl.json` (or alias `ctf`)

### Persistent Login (IMPORTANT)
Browser sessions are persisted in `~/.ctf-browser-data/`.
- **First time per platform**: Claude navigates to login page, asks user for credentials, logs in via Playwright. Session cookie is saved automatically.
- **Subsequent sessions**: Cookie is reused. No re-login needed.
- **Session expired**: Claude detects login page redirect, re-prompts user.
- **NEVER store passwords in files.** Only browser cookies persist.

### Intake Procedure
1. Navigate to platform challenge page (Playwright or Chrome MCP)
2. Detect login state — if login page, ask user for credentials and log in
3. Read challenge page: category, description, attachments, remote host/port
4. Download attachments to `_downloads/`
5. Scaffold challenge folder:
   ```bash
   # WSL:
   mkdir -p challenges/<name>/{artifacts,memory,deploy}
   # Windows:
   powershell.exe -ExecutionPolicy Bypass -File scripts\scaffold.ps1 -Name "<name>" -Category "<cat>"
   ```
6. Extract downloaded files to `challenges/<name>/deploy/`
7. Write `challenges/<name>/meta.yaml` with remote info
8. Start solving with the appropriate category pipeline

### Category Mapping
- Crypto / 암호학 / Cryptography -> crypto
- Pwnable / 시스템 해킹 / Binary Exploitation -> pwn
- Web / 웹 해킹 / Web Exploitation -> web
- Reversing / 리버싱 / Reverse Engineering -> rev
- Blockchain / Web3 -> web3
- Forensics / 포렌식 / Digital Forensics -> forensics
- AI / ML -> ai
- Misc / Miscellaneous -> misc

### Edge Cases
- Login required: navigate to login page, ask user for credentials, log in via browser.
- Multiple attachments: download all to same challenge folder.
- Existing folder: append timestamp suffix to avoid collision.
- No attachments (remote only): record host:port in meta.yaml, proceed to recon.

---

## 10. Learning Loop & Knowledge System

### Knowledge Base Structure
```
knowledge/
├── index.md                    # Master challenge index (solved/attempted)
├── CTF_SPEEDRUN_MEMORY.md      # Quick-reference speed patterns
├── techniques/                 # Reusable technique guides
│   └── efficient_solving.md    # Problem type → approach mapping
└── challenges/                 # Per-challenge writeups
    └── <name>.md               # Technique, approach, code snippets
```

### Before Solving
1. Read `knowledge/index.md` — check if already solved or similar challenge exists.
2. Read `knowledge/CTF_SPEEDRUN_MEMORY.md` for matching speed patterns.
3. Read `knowledge/techniques/efficient_solving.md` for problem classification.
4. Search `knowledge/challenges/` for similar past challenges.

### After FLAG_FOUND (MANDATORY — never skip)
Spawn `@reporter` agent immediately after verifier confirms FLAG_FOUND.
Reporter executes this sequence automatically:

```bash
# 1. Record result + auto-generate writeup
python3 tools/learn.py record \
  --challenge-dir challenges/<name> \
  --status success \
  --flag "DH{...}" \
  --category <category>

# 2. Extract reusable technique (if novel)
python3 tools/learn.py extract-technique \
  --challenge-dir challenges/<name> \
  --name "<technique_name>" \
  --category <category>
```

Reporter then enriches the auto-generated writeup and appends speed pattern to `CTF_SPEEDRUN_MEMORY.md`:
```
### <Challenge Name> | <Category> | <Date>
**Fast detection**: <signals that identify this problem type quickly>
**Winning chain**: <what worked and why>
**Failures -> fixes**: <what didn't work and the immediate correction>
**Reusable**: <code snippets, techniques, or checklists to reuse>
**Speedup**: <estimated time savings for next similar challenge>
```

### After FAILURE (also mandatory)
If max retries exhausted without flag, still record:
```bash
python3 tools/learn.py record \
  --challenge-dir challenges/<name> \
  --status failed \
  --category <category> \
  --notes "blocker: <specific reason>"
```

---

## 11. Scaffolding

When starting a new challenge, scaffold with:
```
powershell.exe -ExecutionPolicy Bypass -File scripts\scaffold.ps1 -Name "<name>" -Category "<category>" [-Remote "<host> <port>"]
```

This creates:
```
challenges/<name>/
├── meta.yaml
├── solve.py OR exploit.py
└── memory/
    ├── recon.md
    ├── strategy.md
    ├── discoveries.md
    └── failures.md
```

### Solver Execution
```
powershell.exe -ExecutionPolicy Bypass -File scripts\run.ps1 -Path "challenges\<name>" [-Mode remote]
```

### Exit Gate
```
powershell.exe -ExecutionPolicy Bypass -File scripts\gate.ps1 -Path "challenges\<name>"
```
Checks: meta.yaml exists, solver non-trivial, recon populated, strategy populated.

---

## 12. MCP Servers

Config: `.mcp.json` (11 servers)

| Server | Purpose |
|--------|---------|
| docker | Container management |
| filesystem | File access (project root) |
| github | GitHub API |
| ida-pro-mcp | IDA Pro remote analysis |
| notion | Notion integration |
| pwn-local | checksec / readelf / objdump / ropgadget / run_solve |
| solver-z3 | Z3 SMT solver |
| py-repl | Python REPL |
| solver-pysat | PySAT boolean solver |
| sage-helper | SymPy symbolic math |
| solver-cryptominisat | CryptoMiniSat CNF/XOR-SAT |

### Rules
- Ignore MCP errors that don't block the solve.
- If a needed MCP is broken, fall back to CLI tools immediately.
- IDA Pro MCP requires IDA running — if not, use objdump/readelf.

---

## 13. Governance (from KryptoPilot)

### Library Preference Order
Always prefer validated libraries over custom implementations:
1. **Crypto**: SageMath > gmpy2 > pycryptodome > sympy > custom code
2. **Pwn**: pwntools > ropper > manual ROP construction
3. **Web**: requests/curl > custom HTTP client
4. **Rev**: Z3 > angr > manual constraint solving

### Difficulty Self-Assessment
Before diving deep, self-assess the challenge difficulty:
- **L1-L2** (straightforward): Standard patterns, known attacks -> proceed directly
- **L3** (complex): Multi-step, requires chaining -> plan before coding
- **L4** (hard): Requires specialized knowledge -> trigger knowledge acquisition (WebSearch for writeups/papers)
- **L5** (research-grade): Novel technique needed -> extended analysis, multiple approaches

Record assessment in `memory/strategy.md`. If L4+, knowledge acquisition is MANDATORY before writing solver.

---

## 14. Tool Routing (from HexStrike AI)

Before running ANY tool, consider:

1. **Primary tool**: Best tool for this specific task (highest confidence)
2. **Fallback**: What to try if primary fails
3. **Last resort**: Minimal approach that might still work

### Fallback Chains
```
Binary analysis: checksec -> readelf -> objdump -> strings
Port scanning:   nc -zv -> python socket -> nmap (WSL)
Web scanning:    curl -> requests -> Chrome MCP
Crypto math:     sage-helper -> solver-z3 -> py-repl gmpy2
Disassembly:     ida-pro-mcp -> objdump -d -> strings
```

On tool failure: rotate to next in chain immediately. Don't retry the same tool more than twice with the same parameters.

---

## 15. Session Management & Context Economy

### Session Architecture

**NEVER open a new Claude Code session per problem.**
One main session stays alive as an orchestrator. Each problem gets a spawned subagent.

```
Main Session (always on)
│  - Loads CLAUDE.md once
│  - Holds CTF_SPEEDRUN_MEMORY across problems
│  - Orchestrates only — does NOT accumulate problem noise
│
├─ Agent subagent (problem A)  ← isolated context window
├─ Agent subagent (problem B)  ← isolated context window
└─ Agent subagent (problem C)  ← isolated context window
```

### How to Spawn a Subagent

Use the `Agent` tool with a fully-specified prompt. The subagent gets NO implicit context — everything must be in the prompt:

```
Agent(
  subagent_type = "general-purpose",   # or any .claude/agents/*.md role
  isolation     = "worktree",           # git worktree isolation (file ops safe)
  run_in_background = True,             # parallel execution
  prompt = """
    Challenge: <name>, Category: <crypto|pwn|web|rev>
    Path: challenges/<name>/
    Remote: <host>:<port>  (if any)
    Files: <list key files>

    Follow CLAUDE.md pipeline for <category>.
    Key facts: <any critical info recon found>
    Goal: recover flag, write to memory/discoveries.md, return flag string.
  """
)
```

**What the subagent gets:**
- Clean context (no other problem's logs)
- Full tool access (MCP, Bash, files)
- worktree isolation → writes don't conflict with other agents

**What the subagent does NOT get:**
- Main session's conversation history
- Other agents' context
→ Must pass ALL needed facts in the prompt.

### Parallel Solving (3 problems at once)

```python
# Main session spawns 3 agents simultaneously:
Agent(prompt="solve challenges/prob_A ...", run_in_background=True)
Agent(prompt="solve challenges/prob_B ...", run_in_background=True)
Agent(prompt="solve challenges/prob_C ...", run_in_background=True)
# All 3 run in parallel. Main session waits for results.
```

### /compact Timing Rules

Run `/compact` in the **main session** at these trigger points:

| Trigger | Action |
|---------|--------|
| Problem solved (flag recovered) | `/compact` — summarize and drop problem context |
| After 3+ problems in one session | `/compact` — prevent context bloat |
| Context > ~80k tokens | `/compact` immediately |
| Before spawning 3+ parallel agents | `/compact` — free headroom for orchestration |

**What to preserve before /compact:**
- Flag(s) already found — print them out first
- Any reusable snippets → already in `knowledge/CTF_SPEEDRUN_MEMORY.md`
- The memory/ files are on disk — they survive /compact automatically

### Token Budget Rules

```
Main session budget target: < 30k tokens at any time
Per-subagent budget:        unlimited (isolated window)
After /compact:             main session resets to ~5k baseline
```

If you are the main session and context is growing due to direct solving (not orchestration), you are doing it wrong — spawn a subagent instead.
