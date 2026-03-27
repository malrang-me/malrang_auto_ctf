# CLAUDE.md — malrang_auto_ctf

Autonomous CTF solving framework for Claude Code.
BASE = `C:\Users\malrangme\Desktop\malrang_auto_ctf`

---

## 1. Goal

- Every challenge runs end-to-end: analyze -> write solver -> execute -> verify -> report flag.
- "Idea only" is never acceptable. Completion = flag recovered + verified + reported for manual submission.
- The recovered flag MUST be printed clearly in the final report so the user can copy-paste it.

---

## 2. Core Rules

1. **Challenge folder isolation**: All problem-specific files (solve.py, exploit.py, memory/, artifacts/) go inside `challenges/<name>/` only. Never write challenge files outside the challenge folder.
2. **Reuse before create**: Before creating any file, Glob for existing code/artifacts. Prefer editing over creating.
3. **Evidence required**: No guessed constants, offsets, or formulas. Every key decision must have a code/output/log basis. Record reasoning in `memory/discoveries.md`.
4. **No auto flag submission**: Never submit flags automatically. Default = recover + verify + report. Only submit if the user explicitly asks in the same turn.
5. **False-positive prevention**: Re-run the solver at least once to confirm the flag is reproducible. For remote challenges, verify the flag came from the actual server, not a local test.
6. **Brute-force timebox**: Any brute-force must have an explicit time limit (10/20/30 min) and abort condition defined before starting.
7. **Final report format**: (1) What was done (2) How it was verified (3) Remaining risks or caveats.

---

## 3. Loop Detection

Track failure signatures. A failure signature = same error class + same approach.

- **3 same-signature failures**: WARNING. You MUST change at least one assumption, parameter, or approach before retrying. Write the change to `memory/failures.md`.
- **5 same-signature failures**: HARD STOP. You MUST switch to a fundamentally different approach. Document all failed attempts and why they failed in `memory/failures.md` before proceeding.
- **Never**: Retry the exact same thing hoping for a different result. If it failed 3 times, it will fail a 4th time.

---

## 4. Flag Verification

A flag candidate is valid ONLY if ALL of these are true:

1. It appears in actual solver execution output (stdout/stderr from running solve.py/exploit.py).
2. It matches the expected flag format (e.g., `DH{...}`, `flag{...}`, `CTF{...}`).
3. It is NOT from: `strings` output, placeholder text, comments in source code, local test flag files, or challenge description.
4. For remote challenges: the flag came from the actual target server, not a local binary.

On finding a candidate: re-run the solver once to confirm reproducibility before reporting.

---

## 5. Five-Minute Gate

Execute these steps at the start of EVERY challenge:

1. **Connectivity**: If remote, verify with `nc -zv <host> <port>` or Python socket.
2. **First contact**: Connect once, capture banner/prompt/I-O format.
3. **Local check**: Verify local execution + dependencies.
4. **Classify**: Determine category. Read `categories/<category>.md` for attack patterns.
5. **Speedrun memory**: Read `knowledge/CTF_SPEEDRUN_MEMORY.md` for matching patterns.
6. **Recon**: Write initial analysis to `memory/recon.md`.
7. **Strategy**: Define solver-a and solver-b hypotheses in `memory/strategy.md`.

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

## 7. Parallel Solving

Two solver branches for non-trivial challenges:

- **solver-a** (orthodox): high-confidence, textbook approach. Leak-based, deterministic, proven technique.
- **solver-b** (alternative): different assumption axis. Bypass, unconventional gadget, or alternative vulnerability.

Rules:
- solver-b MUST NOT duplicate solver-a's first candidate.
- Both hypotheses recorded in `memory/strategy.md` before implementation.
- Use Claude Code's `Agent` tool to run branches in parallel when warranted.
- If one branch succeeds, stop the other.
- If both fail, analyze in `memory/failures.md` and formulate solver-c.

---

## 8. Dreamhack Auto-Intake

### Trigger
User says "solve <problem_name>" or provides a Dreamhack URL.

### Procedure (Chrome MCP)
1. `tabs_context_mcp` -> get/create tab
2. `navigate` to `https://dreamhack.io`
3. `find` search input -> `form_input` problem name -> search
4. Click result -> enter challenge detail page
5. `read_page` to collect: category, attachments, remote host/port
6. Download attachments to `_downloads/`
7. Run intake script:
   ```
   powershell.exe -ExecutionPolicy Bypass -File scripts\intake.ps1 -ProblemName "<name>" -Category "<category>"
   ```
8. Start solving with the appropriate category rules.

### Category Mapping
- Crypto / 암호학 -> crypto
- Pwnable / 시스템 해킹 -> pwn
- Web / 웹 해킹 -> web
- Reversing / 리버싱 -> rev
- Blockchain / Web3 -> web3
- Forensics / 포렌식 -> forensics
- AI -> ai
- Misc -> misc

### Edge Cases
- Login required: guide user to log in, wait, then resume.
- Multiple attachments: download all to same challenge folder.
- Existing folder: append timestamp suffix to avoid collision.

---

## 9. Learning Loop

### Before Solving
Read `knowledge/CTF_SPEEDRUN_MEMORY.md` and apply any matching patterns.

### After Solving
Append a new entry with this structure:
```
---
### <Challenge Name> | <Category> | <Date>
**Fast detection**: <signals that identify this problem type quickly>
**Winning chain**: <what worked and why>
**Failures -> fixes**: <what didn't work and the immediate correction>
**Reusable**: <code snippets, techniques, or checklists to reuse>
**Speedup**: <estimated time savings for next similar challenge>
```

---

## 10. Scaffolding

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

## 11. MCP Servers

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
