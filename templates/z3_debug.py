#!/usr/bin/env python3
"""
Z3 Constraint Debugging Framework for CTF Reversing.

When Z3 returns UNSAT or gives wrong results, this framework helps diagnose:
  1. UNSAT core extraction (which constraints conflict?)
  2. Incremental constraint testing (add one-by-one, find first failure)
  3. Known I/O pair validation (test model against known input/output)
  4. Constraint logging with named groups
  5. GDB oracle feedback loop (use binary as ground truth)

Usage:
  # Copy to challenge dir, import and use ConstraintDebugger
  from z3_debug import ConstraintDebugger
  dbg = ConstraintDebugger(bits=32)
  dbg.add_vars("flag", 16)  # 16 input bytes
  dbg.add("transform", flag[0] + 0x42 == 0x83)
  dbg.add("check", flag[0] ^ 0x55 == expected[0])
  result = dbg.solve()
  # If UNSAT: dbg.diagnose() shows which constraint group conflicts

Standalone test:
  python templates/z3_debug.py --test   # run self-test
"""

import sys
import json
import subprocess
from pathlib import Path

try:
    from z3 import (
        BitVec, BitVecVal, Solver, sat, unsat, unknown,
        RotateLeft, RotateRight, LShR, URem, UDiv,
        And, Or, Not, Xor, If,
        set_param, is_bv_value
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    print("[!] z3-solver not installed. pip install z3-solver")


class ConstraintDebugger:
    """Z3 solver with constraint grouping, UNSAT diagnosis, and oracle validation."""

    def __init__(self, bits=8, word_bits=32):
        """
        Args:
            bits: default BitVec width for input variables
            word_bits: word size for computations (8/16/32/64)
        """
        if not Z3_AVAILABLE:
            raise ImportError("z3-solver required")

        self.bits = bits
        self.word_bits = word_bits
        self.mask = (1 << word_bits) - 1
        self.solver = Solver()
        self.vars = {}           # name -> list[BitVec]
        self.groups = {}         # group_name -> list[constraint]
        self.group_order = []    # insertion order
        self._log = []           # constraint log for replay

    # ── Variable Creation ──────────────────────────��───────────────────

    def add_vars(self, name: str, count: int, bits: int = None) -> list:
        """Create a group of BitVec variables (e.g., 16 input bytes)."""
        b = bits or self.bits
        vs = [BitVec(f"{name}_{i}", b) for i in range(count)]
        self.vars[name] = vs
        return vs

    def add_var(self, name: str, bits: int = None):
        """Create a single BitVec variable."""
        b = bits or self.word_bits
        v = BitVec(name, b)
        self.vars[name] = [v]
        return v

    # ── Constraint Addition ────────────────────────────────────────────

    def add(self, group: str, *constraints):
        """Add constraints under a named group (for UNSAT diagnosis)."""
        if group not in self.groups:
            self.groups[group] = []
            self.group_order.append(group)
        for c in constraints:
            self.groups[group].append(c)
            self.solver.add(c)
            self._log.append((group, str(c)))

    def add_range(self, group: str, var_list, lo=0x20, hi=0x7e):
        """Constrain variables to a range (default: printable ASCII)."""
        for v in var_list:
            self.add(group, v >= lo, v <= hi)

    def add_prefix(self, group: str, var_list, prefix: bytes):
        """Constrain first N bytes to a known prefix (e.g., b'DH{')."""
        for i, b in enumerate(prefix):
            if i < len(var_list):
                self.add(group, var_list[i] == b)

    # ── Solving ────────────────────────────────────────────────────────

    def solve(self) -> dict | None:
        """Solve and return variable values, or None if UNSAT."""
        result = self.solver.check()
        if result == sat:
            m = self.solver.model()
            solution = {}
            for name, vs in self.vars.items():
                vals = []
                for v in vs:
                    ev = m.eval(v, model_completion=True)
                    vals.append(ev.as_long() if is_bv_value(ev) else None)
                solution[name] = vals
            return solution
        elif result == unsat:
            print("[Z3] UNSAT - use diagnose() to find conflicting constraints")
            return None
        else:
            print(f"[Z3] Result: {result} (timeout or unknown)")
            return None

    def solve_bytes(self, var_name: str = "flag") -> bytes | None:
        """Solve and return as byte string."""
        sol = self.solve()
        if sol and var_name in sol:
            return bytes(v if v is not None else 0 for v in sol[var_name])
        return None

    # ── UNSAT Diagnosis ────────────────────────────────────────────────

    def diagnose(self) -> dict:
        """Diagnose UNSAT by testing constraint groups incrementally.

        Returns dict with:
          - "status": "sat" or "unsat"
          - "conflicting_group": first group that causes UNSAT when added
          - "minimal_conflict": smallest set of conflicting groups
          - "group_results": {group_name: "sat"/"unsat"} in order
        """
        print("\n[Z3 Diagnosis] Testing constraint groups incrementally...")
        result = {
            "status": "unknown",
            "conflicting_group": None,
            "minimal_conflict": [],
            "group_results": {},
        }

        test_solver = Solver()
        first_unsat = None

        for group_name in self.group_order:
            constraints = self.groups[group_name]
            for c in constraints:
                test_solver.add(c)

            check = test_solver.check()
            status = "sat" if check == sat else "unsat" if check == unsat else "unknown"
            result["group_results"][group_name] = status
            n_constraints = len(constraints)
            print(f"  + {group_name} ({n_constraints} constraints) -> {status}")

            if check == unsat and first_unsat is None:
                first_unsat = group_name
                result["conflicting_group"] = group_name
                result["status"] = "unsat"
                break

        if first_unsat is None:
            result["status"] = "sat"
            print("  All groups together are SAT (no conflict found)")
            return result

        # Phase 2: find minimal conflict set
        print(f"\n[Z3 Diagnosis] Minimal conflict search (conflicting: {first_unsat})...")
        minimal = self._find_minimal_conflict(first_unsat)
        result["minimal_conflict"] = minimal
        if minimal:
            print(f"  Minimal conflict: {minimal}")

        # Phase 3: suggest fixes
        print(f"\n[Z3 Diagnosis] Suggestions:")
        self._suggest_fixes(first_unsat, result)

        return result

    def _find_minimal_conflict(self, failing_group: str) -> list[str]:
        """Find minimal set of groups that cause UNSAT with failing_group."""
        failing_constraints = self.groups[failing_group]

        # Test each prior group individually with the failing group
        conflicting = []
        for group_name in self.group_order:
            if group_name == failing_group:
                break

            test_solver = Solver()
            for c in self.groups[group_name]:
                test_solver.add(c)
            for c in failing_constraints:
                test_solver.add(c)

            if test_solver.check() == unsat:
                conflicting.append(group_name)

        return conflicting + [failing_group]

    def _suggest_fixes(self, failing_group, result):
        """Print diagnostic suggestions based on failure pattern."""
        suggestions = [
            "1. Verify expected values: re-read constants from binary/GDB",
            "2. Check signedness: BitVec operations are unsigned by default",
            "   - Use SignExt() for signed, ZeroExt() for unsigned widening",
            "3. Check operation order: trace forwards from input to output",
            "4. Check modular arithmetic: missing & MASK after operations?",
            "5. Test with known I/O pair: dbg.validate_known(input_bytes, expected_output)",
            "6. Check for missing constraints: are ALL conditions from the binary captured?",
        ]
        for s in suggestions:
            print(f"  {s}")

    # ── Known I/O Validation ───────────────────────────────────────────

    def validate_known(self, var_name: str, known_input: bytes,
                       expected_results: dict[str, list[int]]) -> bool:
        """Test constraints against a known input/output pair.

        Args:
            var_name: variable group name (e.g., "flag")
            known_input: known correct input bytes
            expected_results: {group_name: [expected_values]} for CHECK groups
        """
        print(f"\n[Z3 Validate] Testing known input: {known_input.hex()}")

        test_solver = Solver()
        vs = self.vars.get(var_name, [])

        # Fix input to known values
        for i, b in enumerate(known_input):
            if i < len(vs):
                test_solver.add(vs[i] == b)

        # Add all constraints
        for group_name, constraints in self.groups.items():
            for c in constraints:
                test_solver.add(c)

        result = test_solver.check()
        if result == sat:
            print("  PASS: known input satisfies all constraints")
            return True
        else:
            print("  FAIL: known input violates constraints!")
            # Find which group fails
            test_solver2 = Solver()
            for i, b in enumerate(known_input):
                if i < len(vs):
                    test_solver2.add(vs[i] == b)

            for group_name in self.group_order:
                for c in self.groups[group_name]:
                    test_solver2.add(c)
                if test_solver2.check() == unsat:
                    print(f"  First failing group: {group_name}")
                    print(f"  -> Check if constraints in '{group_name}' match the binary")
                    break
            return False

    # ── GDB Oracle Feedback ────────────────────────────────────────────

    def oracle_validate(self, binary_path: str, input_bytes: bytes,
                        check_format: str = "DH{") -> bool:
        """Run binary with input, check if output contains success indicator.

        Use as ground-truth to validate Z3 model.
        """
        print(f"\n[Oracle] Running binary with input: {input_bytes[:20]}...")
        try:
            r = subprocess.run(
                ["wsl", binary_path] if sys.platform == "win32" else [binary_path],
                input=input_bytes + b"\n",
                capture_output=True, timeout=10,
            )
            stdout = r.stdout.decode("latin-1", errors="replace")
            stderr = r.stderr.decode("latin-1", errors="replace")
            output = stdout + stderr

            success = check_format in output or "correct" in output.lower() or "success" in output.lower()
            print(f"  stdout: {stdout[:100]}")
            print(f"  Result: {'SUCCESS' if success else 'FAIL'}")
            return success
        except subprocess.TimeoutExpired:
            print("  TIMEOUT")
            return False
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    # ── Constraint Log ─────────────────────────────────────────────────

    def print_log(self):
        """Print all constraints added, grouped by name."""
        print("\n[Z3 Log] All constraints:")
        for group_name in self.group_order:
            constraints = self.groups[group_name]
            print(f"\n  [{group_name}] ({len(constraints)} constraints)")
            for i, c in enumerate(constraints):
                s = str(c)
                if len(s) > 100:
                    s = s[:97] + "..."
                print(f"    {i}: {s}")

    def stats(self) -> dict:
        """Return solver statistics."""
        total = sum(len(cs) for cs in self.groups.values())
        return {
            "groups": len(self.groups),
            "total_constraints": total,
            "variables": {name: len(vs) for name, vs in self.vars.items()},
            "group_sizes": {name: len(cs) for name, cs in self.groups.items()},
        }


# ============================================================================
# Standalone self-test
# ============================================================================

def _self_test():
    """Run self-test to verify the framework works."""
    print("=== Z3 Debug Framework Self-Test ===\n")

    # Test 1: Simple solvable system
    print("[Test 1] Simple solvable system")
    dbg = ConstraintDebugger(bits=8, word_bits=8)
    flag = dbg.add_vars("flag", 4)
    dbg.add_range("range", flag, 0x20, 0x7e)
    dbg.add("check0", (flag[0] + 0x10) & 0xFF == 0x51)  # flag[0] = 0x41 = 'A'
    dbg.add("check1", flag[1] ^ 0x20 == 0x62)            # flag[1] = 0x42 = 'B'
    dbg.add("check2", (flag[2] - 0x01) & 0xFF == 0x42)   # flag[2] = 0x43 = 'C'
    dbg.add("check3", flag[3] == 0x44)                    # flag[3] = 0x44 = 'D'

    result = dbg.solve_bytes("flag")
    assert result == b"ABCD", f"Expected ABCD, got {result}"
    print(f"  PASS: {result}\n")

    # Test 2: UNSAT diagnosis
    print("[Test 2] UNSAT diagnosis")
    dbg2 = ConstraintDebugger(bits=8, word_bits=8)
    x = dbg2.add_vars("x", 1)
    dbg2.add("constraint_a", x[0] == 0x41)
    dbg2.add("constraint_b", x[0] == 0x42)  # conflicts with a

    result2 = dbg2.solve()
    assert result2 is None
    diag = dbg2.diagnose()
    assert diag["conflicting_group"] == "constraint_b"
    print(f"  PASS: Correctly identified conflicting group: {diag['conflicting_group']}\n")

    # Test 3: Known I/O validation
    print("[Test 3] Known I/O validation")
    dbg3 = ConstraintDebugger(bits=8, word_bits=8)
    flag3 = dbg3.add_vars("flag", 2)
    dbg3.add("range", flag3[0] >= 0x20, flag3[0] <= 0x7e, flag3[1] >= 0x20, flag3[1] <= 0x7e)
    dbg3.add("transform", (flag3[0] + flag3[1]) & 0xFF == 0x83)  # 0x41+0x42=0x83

    ok = dbg3.validate_known("flag", b"AB", {})
    assert ok, "Known input validation should pass"
    print(f"  PASS: Known input validated\n")

    # Test 4: Stats
    print("[Test 4] Stats")
    stats = dbg.stats()
    print(f"  {stats}")
    assert stats["groups"] == 5  # range + check0-3
    print(f"  PASS\n")

    print("=== All tests passed ===")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Z3 Constraint Debugging Framework")
    p.add_argument("--test", action="store_true", help="Run self-test")
    args = p.parse_args()

    if args.test:
        _self_test()
    else:
        print("Z3 Debug Framework - import and use ConstraintDebugger class")
        print("Run --test for self-test")
