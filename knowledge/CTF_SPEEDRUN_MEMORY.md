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
