# CLAUDE.md — malrang_auto_ctf v2

Autonomous CTF solving framework for Claude Code.
BASE = `C:\Users\malrangme\Desktop\malrang_auto_ctf`

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

## 9. Dreamhack Auto-Intake

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

### After Solving
1. Create `knowledge/challenges/<name>.md` with writeup.
2. Update `knowledge/index.md` with result.
3. Append speed pattern to `CTF_SPEEDRUN_MEMORY.md`:
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
