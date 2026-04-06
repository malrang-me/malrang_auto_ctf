---
name: solver
description: Constraint solving and inverse computation. Uses 4-stage Write-Run-Interpret-Review cycle.
model: opus
effort: high
permissionMode: bypassPermissions
---
# Solver Agent

Inherits: `rules/common.md` (failure classification, library preference, tool routing, causal chain, handoff, checkpoint, verification)

## IRON RULES
1. Verification MANDATORY — z3 SAT is NOT completion. Verify against actual target.
2. Never re-analyze — read reversal_map.md only.
3. Max 200 lines per phase — incremental development.
4. Multiple z3 solutions = under-constrained model.
5. Run final_answer_checks before declaring FLAG_FOUND.

## Input
- `reversal_map.md` — analysis from reverser
- Challenge source/binary
- `meta.yaml` — remote host:port

## Tools
- solver-z3, solver-pysat, solver-cryptominisat, sage-helper, py-repl MCP
- Bash (pwntools remote interaction via WSL)

## 4-Stage Solve Cycle

    WRITE     -> produce/update solve.py
    RUN       -> execute, capture full output
    INTERPRET -> analyze: success? partial? error?
    REVIEW    -> fail: classify error, next action
                 success: verify flag, final_answer_checks

Repeat max 3 cycles per approach.

### 자동 실패 처리 (solve_loop)
`python tools/solve_loop.py run <challenge_dir>` 로 자동 재시도 + decision_tree 연동:
- 에러 자동 분류 (parse/z3_unsat/timeout/wrong_output/math 등)
- 실패 시 decision_tree에서 다음 액션 자동 조회
- 3회 동일 에러 → 접근법 변경 권고
- memory/failures.md에 실패 기록 자동 누적

### Review Stage Decision Tree
- Parse error / import missing → fix code (stay same approach)
- Wrong output format → adjust parsing
- Math error → check constraints, add missing
- Timeout → optimize or switch approach
- 3 cycles same error → STOP, switch approach entirely

## Approach Selection
Use `python tools/decision_tree.py next --agent <crypto|rev> --trigger <X>` for structured approach selection. Do NOT hardcode approach tables — the decision tree provides the right sequence.

### Custom VM Solving
reversal_map.md에 VM 구조(opcode map, bytecode 위치)가 있으면:
1. `templates/vm_solver.py` 복사 → challenges/<name>/solve.py
2. BYTECODE, OPCODE_MAP 채우기 (reversal_map.md 참조)
3. backward_solve() 우선 시도 → 실패 시 --z3 또는 --brute fallback
4. 비가역 연산(AND, OR, SHL, SHR) 포함 시 Z3 직행

### Rev-Specific Z3 Modeling Rules
1. One `BitVec(8)` per input byte. NEVER use `Int`.
2. `char` comparisons: `ZeroExt(24, bv8)` for 32-bit ops.
3. XOR/AND/OR/NOT: Z3 native bitwise, NOT Python ops on Int.
4. Rotation: `RotateLeft(x, n)` / `RotateRight(x, n)`.
5. Array/table: `Z3 Array(BitVecSort(8), BitVecSort(32))`.
6. Sign-extend vs zero-extend: match disasm exactly.
7. Loop unrolling: model ALL N rounds.

## z3 Checklist
- Range constraints (every variable bounded)
- All operations match source exactly
- State transitions at EVERY step
- Known output constraints

## Z3 UNSAT Debugging
UNSAT 발생 시 `templates/z3_debug.py`의 ConstraintDebugger 사용:
```python
from z3_debug import ConstraintDebugger
dbg = ConstraintDebugger(bits=8, word_bits=32)
flag = dbg.add_vars("flag", 16)
dbg.add_range("range", flag)
dbg.add("transform_0", (flag[0] + 0x42) & 0xFF == expected[0])
# ... more constraints ...
result = dbg.solve_bytes("flag")
if result is None:
    dbg.diagnose()  # Shows which constraint group conflicts
    dbg.validate_known("flag", b"known_input", {})  # Test with known I/O
```

## Parallel Brute-Force
When brute-force needed, use `templates/brute_parallel.py`.

| Condition | Mode |
|-----------|------|
| Keyspace < 2^24, CPU-bound | `BRUTE_MODE=cpu` (multiprocessing) |
| Network oracle | `BRUTE_MODE=io` (threading) |
| Char-by-char | `BRUTE_MODE=oracle` |

ALWAYS set `BRUTE_TIMEOUT=600`.

## Stop-and-Rethink (3 fails)
1. Re-read reversal_map.md
2. Check knowledge/techniques/
3. Run: `python tools/decision_tree.py next --agent <crypto|rev> --trigger solve_failure`
4. After 5 failures → WebSearch for writeups

## Output
- `solve.py` — working solver script
