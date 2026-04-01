# CTF Pipeline — Automatic Selection & Execution

## Pipeline Selection (MANDATORY)

```
if trivial (source provided, logic bug visible in 1-3 lines, one-liner exploit):
    ctf-solver 1-agent (model=sonnet) → reporter
elif type == "pwn" and vuln clear:
    reverser → chain → critic → verifier → reporter  (5-agent)
elif type == "pwn" and vuln unclear:
    reverser → trigger → chain → critic → verifier → reporter  (6-agent)
elif type == "crypto":
    reverser → solver → critic → verifier → reporter  (5-agent)
elif type == "reversing":
    reverser → solver → critic → verifier → reporter  (5-agent)
elif type == "web":
    scout → analyst → exploiter → reporter  (4-agent)
elif type == "web3":
    reverser → solver → critic → verifier → reporter  (5-agent)
```

**Never use full 6-agent pipeline unconditionally.** Unnecessary agents = token waste.

## Structured Handoff Protocol

All agent-to-agent transitions MUST use this format:

```
[HANDOFF from @<agent> to @<next_agent>]
- Finding/Artifact: <filename>
- Confidence: PASS / PARTIAL / FAIL
- Key Result: <1-2 sentence core result>
- Next Action: <specific task for next agent>
- Blockers: <if any, else "None">
```

## Context Positioning (Lost-in-Middle Prevention)

```
[Lines 1-2] Critical Facts — key addresses, offsets, vuln type, FLAG conditions
[Lines 3-5] Remote info — host:port, platform, interaction limit
[Middle]    Agent definition (auto-loaded from .claude/agents/)
[End]       HANDOFF detail (full context, previous failure history)
```

## Agent Model Assignment (MANDATORY)

| Agent | Model | Reason |
|-------|-------|--------|
| reverser | sonnet | Structure analysis, pattern matching |
| solver | opus | Complex inverse computation, lattice |
| chain | opus | Multi-stage exploit design |
| trigger | opus | Crash discovery requires creative fuzzing |
| critic | opus | Cross-verification, logic error detection |
| verifier | sonnet | Execution + verification |
| reporter | sonnet | Documentation |
| scout | sonnet | Web recon, CWE checklist |
| analyst | opus | Vuln confirmation requires reasoning |
| exploiter | opus | Exploit chain execution |
| ctf-solver | sonnet | Trivial single-agent solve |

## Failure Protocol

- **2 consecutive failures → Dual-Approach**: spawn 2 solver/chain agents with different strategies in parallel. First success wins.
- **4 failures → WebSearch**: mandatory external writeup search.
- **Same failure signature 3x → Stall Mode**: stop current approach, re-examine assumptions, switch chain.

## Dual-Approach Auto-Trigger

When solver/chain fails 2x consecutively:
```
Orchestrator spawns 2 agents simultaneously:
  solver-A (approach A: z3/formal) + solver-B (approach B: lattice/sage/brute)
  First success adopted, other terminated.
```

## Fake Flag Protection

- Local flag files are ALWAYS fake. Only `remote(host, port)` yields real flags.
- Orchestrator MUST run solve.py directly to verify any FLAG_FOUND claim.

## Checkpoint Protocol

All work agents must maintain `<challenge_dir>/checkpoint.json`:
```json
{
  "agent": "solver",
  "status": "in_progress|completed|error",
  "phase": 2,
  "phase_name": "constraint_modeling",
  "completed": ["recon", "structure_analysis"],
  "in_progress": "z3_formulation",
  "critical_facts": {"n_bits": 1024, "vuln": "phi_leaked"},
  "expected_artifacts": ["solve.py"],
  "produced_artifacts": [],
  "timestamp": "2026-03-29T12:00:00"
}
```
