# REV — Reverse Engineering

## MCP Tools
- **pwn-local**: readelf, objdump, checksec | **solver-z3**: constraints | **solver-pysat**: boolean SAT
- **sage-helper**: algebraic constraints | **py-repl**: scripting
- WSL: gdb, ltrace, strace, strings, objdump

## Mandatory First Steps
1. `file` → arch, linking, stripped?
2. `checksec` → protections
3. `readelf -h -l -S` → segments, entry
4. `strings | grep -iE 'flag|DH\{|password|correct|wrong'` (filtered!)
5. Decompile key functions (Ghidra → objdump fallback)
6. Dynamic trace with sample input

## Attack Patterns

### Static
- Control flow → validation function, input path
- Constraint extraction → Z3/SAT model
- Constants → XOR keys, S-boxes, lookup tables
- Anti-debug → ptrace, timing, self-modifying code

### Dynamic
- GDB breakpoints at comparisons
- ltrace/strace for library calls
- Patch-and-run: NOP anti-debug, force branches

### Constraint Solving
- Z3: one BitVec per input byte + constraints from validation
- Angr: symbolic execution with state exploration
- SAT: boolean circuits to CNF
- Custom VM: opcode table → constraint system

## Token-Efficient Tool Chain (IDA급 절감 도구)
```bash
# uncompyle6: dis 바이트코드 수백줄 → Python 소스 복원 (83% 절감)
wsl uncompyle6 file.pyc > source.py  # 소스 있으면 Z3도 필요 없을 수 있음

# IDA MCP: objdump 5000줄 → decompile 200줄 (97% 절감)
# angr: 수동 constraint 추출 → 자동 symbolic execution
wsl python3 templates/angr_solve.py <binary> <find_addr> <avoid_addr>
```

## Tool Routing
| Task | Primary | Fallback |
|------|---------|----------|
| Decompile (ELF/PE) | `tools/ida_headless.py full` (1회 덤프) | `ghidra_decompile.py` |
| Metadata dump (ELF/PE) | `tools/ida_headless.py metadata` | `readelf` + `objdump` |
| Interactive patch | `tools/ida_headless.py patch --script X` | IDA MCP `py_eval` (예외적) |
| Post-dump 조회 | `Read decompiled/<func>.c`, `Grep <pat> decompiled/` | — |
| Decompile (bytecode) | `tools/decompile_bytecode.py decompile` | 개별 도구 직접 호출 |
| Decompile (Python) | `uncompyle6` (소스 복원) | `pycdc` / `python -m dis` |
| Decompile (Java) | `jadx` | `procyon` / `javap -c -p` |
| Constraint solve | solver-z3 MCP | solver-pysat MCP |
| Anti-debug detect | `tools/gdb_auto.py detect` | `strings \| grep ptrace` |
| Anti-debug bypass | `tools/gdb_auto.py bypass` / `patch` | GDB `set $rax=0` |
| Custom VM solve | `templates/vm_solver.py` (backward/z3/brute) | manual |
| Side-channel | `perf stat -e instructions:u` | timing |

**IDA MCP vs headless**: 일반 분석은 headless. MCP는 런타임 인터랙티브 작업(복잡한 xref 체인, 라이브 패치)에만 제한적으로 사용. 일반 `decompile`/`list_funcs`/`imports` MCP 호출은 금지(중복).

## Decision Tree Triggers
```bash
python tools/decision_tree.py next --agent rev --trigger solver_fallback
python tools/decision_tree.py next --agent rev --trigger custom_vm
python tools/decision_tree.py next --agent rev --trigger z3_unsat
python tools/decision_tree.py next --agent rev --trigger anti_debug
```

## Templates
- `templates/angr_solve.py` — symbolic execution + explosion prevention (DFS/veritesting/loop bound)
- `templates/vm_solver.py` — custom VM opcode solver (backward/z3/brute)
- `templates/z3_debug.py` — Z3 UNSAT diagnosis (constraint grouping, incremental test, oracle)
- `templates/interactive_rev.py` — multi-round TCP + solve
- `templates/gdb_auto_analyze.py` — auto cmp breakpoints (legacy, use tools/gdb_auto.py)

## Pitfalls
- Z3 model completeness: capture ALL constraints
- Angr: limit with `avoid` addresses + `angr.options.LAZY_SOLVES`
- Anti-debug: **`tools/gdb_auto.py detect`** 먼저 실행 → bypass 후 분���
- Stripped: use FLIRT signatures or string cross-refs
- Custom VM: opcode map 불완전하면 풀이 실패 → IDA에서 모든 case 확인
- 난독화 참조: `knowledge/techniques/obfuscation_patterns.md`

## Advanced (L4+ only)
- JIT/V8 TurboFan type confusion
- Firmware: binwalk + base address detection
- Side-channel: instruction counting oracle
