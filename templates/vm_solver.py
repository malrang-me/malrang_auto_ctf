#!/usr/bin/env python3
"""
Custom VM Opcode Solver Framework

Reusable framework for reversing custom bytecode VMs in CTF challenges.
Supports: opcode mapping, forward symbolic execution, backward constraint solving.

Usage — customize the OPCODE_MAP and BYTECODE, then run:
  python templates/vm_solver.py                          # solve with backward method
  python templates/vm_solver.py --forward                # verify with forward execution
  python templates/vm_solver.py --z3                     # Z3 fallback for non-invertible ops
  python templates/vm_solver.py --trace ./binary 0x4010a0  # GDB trace at dispatch addr
  python templates/vm_solver.py --extract-switch ./binary   # extract switch/case opcodes

Workflow:
  1. Copy this template to challenges/<name>/solve.py
  2. Fill in BYTECODE (from binary .data or IDA)
  3. Fill in OPCODE_MAP (from decompiled switch/case)
  4. Run solver
"""

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ============================================================================
# Configuration — CUSTOMIZE THESE FOR EACH CHALLENGE
# ============================================================================

# Bytecode: extract from binary (.data section, movabs immediates, etc.)
BYTECODE = b""  # Fill this in

# Word size: 8, 16, 32, or 64 bits
WORD_BITS = 32
WORD_MASK = (1 << WORD_BITS) - 1

# Flag format constraints
FLAG_CHARSET = range(0x20, 0x7f)  # printable ASCII
FLAG_PREFIX = b""                  # e.g., b"DH{" or b"flag{"
FLAG_LEN = 16                      # expected input length

# ============================================================================
# Opcode definitions
# ============================================================================

@dataclass
class Opcode:
    code: int
    name: str
    n_args: int  # number of immediate bytes consumed after opcode
    # arg_size: bytes per argument (1 = uint8, 2 = uint16, 4 = uint32)
    arg_size: int = 1

    def read_args(self, bytecode: bytes, pc: int) -> tuple[list[int], int]:
        """Read arguments from bytecode at pc. Returns (args, new_pc)."""
        args = []
        for _ in range(self.n_args):
            if self.arg_size == 1:
                args.append(bytecode[pc])
                pc += 1
            elif self.arg_size == 2:
                args.append(struct.unpack_from("<H", bytecode, pc)[0])
                pc += 2
            elif self.arg_size == 4:
                args.append(struct.unpack_from(">I", bytecode, pc)[0])  # big-endian for CHECK
                pc += 4
            else:
                args.append(bytecode[pc])
                pc += 1
        return args, pc


# Standard opcode map — customize per challenge
# Keys are opcode byte values, values are Opcode objects
OPCODE_MAP: dict[int, Opcode] = {
    # Example from Interpret challenge:
    # 0x00: Opcode(0x00, "HALT",     0),
    # 0x01: Opcode(0x01, "LOAD_KEY", 0),
    # 0x02: Opcode(0x02, "ADD",      1),
    # 0x03: Opcode(0x03, "XOR",      1),
    # 0x04: Opcode(0x04, "ROL",      1),
    # 0x05: Opcode(0x05, "CHECK",    1, arg_size=4),  # 4-byte big-endian check value
}

# ============================================================================
# VM State
# ============================================================================

@dataclass
class VMState:
    acc: int = 0           # accumulator register
    pc: int = 0            # program counter
    regs: list = None      # general-purpose registers (optional)
    stack: list = None     # stack (optional)
    key_index: int = 0     # current input byte index
    halted: bool = False
    success: bool = False

    def __post_init__(self):
        if self.regs is None:
            self.regs = [0] * 16
        if self.stack is None:
            self.stack = []


@dataclass
class CheckPoint:
    """Records a CHECK operation: what input bytes were loaded and what ops applied."""
    key_indices: list[int]         # which input bytes contribute
    ops_chain: list[tuple]         # [(op_name, arg), ...] from LOAD to CHECK
    expected: int                  # CHECK comparison value
    pc_at_check: int = 0


# ============================================================================
# Common operation helpers (32-bit default, adjust WORD_BITS)
# ============================================================================

def rol(val: int, n: int) -> int:
    n = n & (WORD_BITS - 1)
    return ((val << n) | (val >> (WORD_BITS - n))) & WORD_MASK

def ror(val: int, n: int) -> int:
    n = n & (WORD_BITS - 1)
    return ((val >> n) | (val << (WORD_BITS - n))) & WORD_MASK

def modinv(a: int, m: int = None) -> int:
    """Modular multiplicative inverse via extended GCD."""
    if m is None:
        m = WORD_MASK + 1
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        return None  # no inverse exists
    return x % m

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

# Forward operation table: (state, arg) -> new_state
FORWARD_OPS = {
    "ADD":     lambda val, arg: (val + arg) & WORD_MASK,
    "SUB":     lambda val, arg: (val - arg) & WORD_MASK,
    "XOR":     lambda val, arg: val ^ arg,
    "AND":     lambda val, arg: val & arg,
    "OR":      lambda val, arg: val | arg,
    "ROL":     lambda val, arg: rol(val, arg),
    "ROR":     lambda val, arg: ror(val, arg),
    "MUL":     lambda val, arg: (val * arg) & WORD_MASK,
    "NOT":     lambda val, arg: (~val) & WORD_MASK,
    "SHL":     lambda val, arg: (val << arg) & WORD_MASK,
    "SHR":     lambda val, arg: (val >> arg) & WORD_MASK,
    "NEG":     lambda val, arg: (-val) & WORD_MASK,
    "INC":     lambda val, arg: (val + 1) & WORD_MASK,
    "DEC":     lambda val, arg: (val - 1) & WORD_MASK,
    "MOD":     lambda val, arg: val % arg if arg != 0 else val,
}

# Inverse operation table: (check_val, arg) -> previous_val
# None means not directly invertible (use Z3 fallback)
INVERSE_OPS = {
    "ADD":     lambda val, arg: (val - arg) & WORD_MASK,
    "SUB":     lambda val, arg: (val + arg) & WORD_MASK,
    "XOR":     lambda val, arg: val ^ arg,  # self-inverse
    "ROL":     lambda val, arg: ror(val, arg),
    "ROR":     lambda val, arg: rol(val, arg),
    "MUL":     lambda val, arg: (val * modinv(arg)) & WORD_MASK if modinv(arg) else None,
    "NOT":     lambda val, arg: (~val) & WORD_MASK,
    "NEG":     lambda val, arg: (-val) & WORD_MASK,
    "INC":     lambda val, arg: (val - 1) & WORD_MASK,
    "DEC":     lambda val, arg: (val + 1) & WORD_MASK,
    # Non-invertible:
    "AND":     None,
    "OR":      None,
    "SHL":     None,  # loses high bits
    "SHR":     None,  # loses low bits
    "MOD":     None,  # many-to-one
}


# ============================================================================
# Bytecode Parser
# ============================================================================

def parse_bytecode(bytecode: bytes, opcode_map: dict[int, Opcode]) -> list[tuple]:
    """Parse bytecode into instruction list: [(opcode_name, [args], pc), ...]"""
    instructions = []
    pc = 0
    while pc < len(bytecode):
        code = bytecode[pc]
        pc += 1
        if code not in opcode_map:
            instructions.append(("UNKNOWN", [code], pc - 1))
            break
        op = opcode_map[code]
        if op.n_args > 0:
            args, pc = op.read_args(bytecode, pc)
        else:
            args = []
        instructions.append((op.name, args, pc))
    return instructions


def trace_checkpoints(bytecode: bytes, opcode_map: dict[int, Opcode]) -> list[CheckPoint]:
    """Symbolically trace bytecode to extract CheckPoints.

    Assumes pattern: LOAD_KEY → operations → CHECK (repeat per input byte).
    Handles accumulator-based VMs where each key byte is processed independently.
    """
    checkpoints = []
    pc = 0
    key_index = 0
    current_ops = []
    current_key_indices = []

    while pc < len(bytecode):
        code = bytecode[pc]
        pc += 1

        if code not in opcode_map:
            break

        op = opcode_map[code]
        if op.n_args > 0:
            args, pc = op.read_args(bytecode, pc)
        else:
            args = []

        name = op.name

        if name == "HALT":
            break
        elif name == "LOAD_KEY":
            current_key_indices = [key_index]
            key_index += 1
            current_ops = []
        elif name == "CHECK":
            expected = args[0] if args else 0
            checkpoints.append(CheckPoint(
                key_indices=list(current_key_indices),
                ops_chain=list(current_ops),
                expected=expected,
                pc_at_check=pc,
            ))
        elif name in ("LOAD_REG", "STORE_REG", "PUSH", "POP", "JMP", "JZ", "JNZ", "CALL", "RET"):
            # Control flow / register ops — add to chain for context
            current_ops.append((name, args[0] if args else 0))
        else:
            # Arithmetic/logic operation on accumulator
            current_ops.append((name, args[0] if args else 0))

    return checkpoints


# ============================================================================
# Backward Solver (primary method)
# ============================================================================

def backward_solve(checkpoints: list[CheckPoint]) -> list[int]:
    """Solve input bytes by reversing operations from CHECK values.

    For each checkpoint: start from expected value, apply inverse ops in reverse order.
    Returns list of recovered input bytes.
    """
    max_key = max(max(cp.key_indices) for cp in checkpoints) + 1
    key = [None] * max_key
    non_invertible = []

    for cp in checkpoints:
        val = cp.expected
        invertible = True

        for op_name, arg in reversed(cp.ops_chain):
            inv_fn = INVERSE_OPS.get(op_name)
            if inv_fn is None:
                invertible = False
                non_invertible.append(cp)
                break
            result = inv_fn(val, arg)
            if result is None:
                invertible = False
                non_invertible.append(cp)
                break
            val = result

        if invertible:
            # Recovered value should be a byte (input char)
            byte_val = val & 0xFF
            for ki in cp.key_indices:
                key[ki] = byte_val
            # Verify forward
            if not _verify_forward(cp, byte_val):
                print(f"  WARNING: forward verification failed for key[{cp.key_indices}]")

    if non_invertible:
        print(f"[!] {len(non_invertible)} checkpoints have non-invertible ops — use --z3")

    return key


def _verify_forward(cp: CheckPoint, input_byte: int) -> bool:
    """Verify a solution by forward execution."""
    acc = input_byte
    for op_name, arg in cp.ops_chain:
        fn = FORWARD_OPS.get(op_name)
        if fn is None:
            return False
        acc = fn(acc, arg)
    return acc == cp.expected


# ============================================================================
# Forward Execution (verification)
# ============================================================================

def forward_execute(bytecode: bytes, opcode_map: dict[int, Opcode],
                    input_bytes: list[int]) -> bool:
    """Execute VM with given input, return True if all CHECKs pass."""
    state = VMState()
    checkpoints = trace_checkpoints(bytecode, opcode_map)

    all_pass = True
    for i, cp in enumerate(checkpoints):
        if not cp.key_indices:
            continue
        ki = cp.key_indices[0]
        if ki >= len(input_bytes) or input_bytes[ki] is None:
            all_pass = False
            continue

        acc = input_bytes[ki]
        for op_name, arg in cp.ops_chain:
            fn = FORWARD_OPS.get(op_name)
            if fn:
                acc = fn(acc, arg)

        if acc != cp.expected:
            print(f"  CHECK #{i} FAIL: got 0x{acc:x}, expected 0x{cp.expected:x}")
            all_pass = False
        else:
            print(f"  CHECK #{i} OK")

    return all_pass


# ============================================================================
# Z3 Fallback Solver
# ============================================================================

def z3_solve(checkpoints: list[CheckPoint]) -> list[int] | None:
    """Z3 constraint solver for non-invertible operations."""
    try:
        from z3 import BitVec, BitVecVal, Solver, sat, RotateLeft, RotateRight, LShR
    except ImportError:
        print("[!] Z3 not available. Install: pip install z3-solver")
        return None

    max_key = max(max(cp.key_indices) for cp in checkpoints) + 1
    key_vars = [BitVec(f"k{i}", WORD_BITS) for i in range(max_key)]

    s = Solver()

    # Constrain to byte range
    for kv in key_vars:
        s.add(kv >= 0, kv < 256)

    # Charset constraints
    if FLAG_CHARSET:
        for kv in key_vars:
            charset_min = min(FLAG_CHARSET)
            charset_max = max(FLAG_CHARSET)
            s.add(kv >= charset_min, kv <= charset_max)

    # Prefix constraints
    for i, b in enumerate(FLAG_PREFIX):
        if i < max_key:
            s.add(key_vars[i] == b)

    # Z3 operation map
    z3_ops = {
        "ADD": lambda v, a: v + BitVecVal(a, WORD_BITS),
        "SUB": lambda v, a: v - BitVecVal(a, WORD_BITS),
        "XOR": lambda v, a: v ^ BitVecVal(a, WORD_BITS),
        "AND": lambda v, a: v & BitVecVal(a, WORD_BITS),
        "OR":  lambda v, a: v | BitVecVal(a, WORD_BITS),
        "ROL": lambda v, a: RotateLeft(v, a),
        "ROR": lambda v, a: RotateRight(v, a),
        "MUL": lambda v, a: v * BitVecVal(a, WORD_BITS),
        "NOT": lambda v, a: ~v,
        "SHL": lambda v, a: v << a,
        "SHR": lambda v, a: LShR(v, a),
        "NEG": lambda v, a: -v,
    }

    for cp in checkpoints:
        if not cp.key_indices:
            continue
        ki = cp.key_indices[0]
        acc = key_vars[ki]

        for op_name, arg in cp.ops_chain:
            fn = z3_ops.get(op_name)
            if fn:
                acc = fn(acc, arg)

        s.add(acc == BitVecVal(cp.expected, WORD_BITS))

    if s.check() == sat:
        m = s.model()
        result = [m.eval(kv).as_long() for kv in key_vars]
        return result
    else:
        print("[!] Z3: UNSAT — check constraints")
        return None


# ============================================================================
# Brute-force Fallback (per-byte, for small keyspace)
# ============================================================================

def brute_solve(checkpoints: list[CheckPoint]) -> list[int]:
    """Brute-force each input byte independently (256 candidates per byte)."""
    max_key = max(max(cp.key_indices) for cp in checkpoints) + 1
    key = [None] * max_key

    for cp in checkpoints:
        if not cp.key_indices:
            continue
        ki = cp.key_indices[0]
        if key[ki] is not None:
            continue

        for candidate in FLAG_CHARSET:
            if _verify_forward(cp, candidate):
                key[ki] = candidate
                break

        if key[ki] is None:
            print(f"  key[{ki}]: no valid byte found!")

    return key


# ============================================================================
# GDB Trace Script Generator
# ============================================================================

def generate_trace_script(binary: str, dispatch_addr: str) -> str:
    """Generate GDB script to log opcode execution at VM dispatch loop."""
    return f"""# VM opcode trace script
# Binary: {binary}
# Dispatch address: {dispatch_addr}
# Run: wsl gdb -batch -x vm_trace.gdb ./{binary}
set pagination off
set confirm off
set logging enabled on
set logging file vm_trace.log
set logging overwrite on

break *{dispatch_addr}
commands
  silent
  printf "PC=%d OPCODE=0x%02x ACC=0x%08x\\n", $rdx, *(unsigned char*)($rip), $rax
  continue
end

run <<< "AAAAAAAAAAAAAAAA"
quit
"""


# ============================================================================
# Switch/Case Extractor (from objdump)
# ============================================================================

def extract_switch_pattern(binary: str) -> str:
    """Analyze binary for switch/case dispatch pattern (VM dispatcher detection)."""
    import subprocess
    try:
        r = subprocess.run(
            ["wsl", "objdump", "-d", "-M", "intel", binary],
            capture_output=True, text=True, timeout=30
        )
        disasm = r.stdout
    except Exception:
        return "Error: could not disassemble"

    # Look for indirect jump (jmp *rax, jmp [table + idx*8]) — common VM dispatch
    dispatch_candidates = []
    for line in disasm.splitlines():
        if 'jmp' in line.lower() and ('*' in line or 'QWORD' in line):
            # Indirect jump — potential VM dispatch
            import re
            m = re.match(r'\s*([0-9a-f]+):', line)
            if m:
                dispatch_candidates.append({
                    "addr": m.group(1),
                    "line": line.strip(),
                })

    report = [f"Found {len(dispatch_candidates)} indirect jump candidates:"]
    for c in dispatch_candidates[:10]:
        report.append(f"  0x{c['addr']}: {c['line']}")

    if not dispatch_candidates:
        report.append("No indirect jumps found — VM may use if/else chain instead of switch")
        report.append("Try: IDA MCP decompile to find dispatch function")

    return "\n".join(report)


# ============================================================================
# Main — solve pipeline
# ============================================================================

def main():
    import argparse
    p = argparse.ArgumentParser(description="Custom VM Opcode Solver Framework")
    p.add_argument("--forward", action="store_true", help="Forward execution (verify)")
    p.add_argument("--z3", action="store_true", help="Z3 constraint solver")
    p.add_argument("--brute", action="store_true", help="Brute-force per byte")
    p.add_argument("--trace", nargs=2, metavar=("BINARY", "ADDR"), help="Generate GDB trace script")
    p.add_argument("--extract-switch", metavar="BINARY", help="Extract switch/case pattern")
    p.add_argument("--input", default="", help="Input bytes (hex) for forward verification")
    args = p.parse_args()

    if args.trace:
        script = generate_trace_script(args.trace[0], args.trace[1])
        Path("vm_trace.gdb").write_text(script)
        print("[+] GDB trace script: vm_trace.gdb")
        return

    if args.extract_switch:
        print(extract_switch_pattern(args.extract_switch))
        return

    if not BYTECODE:
        print("[!] BYTECODE is empty — fill in the bytecode from the challenge binary")
        print("    See top of file for configuration section")
        sys.exit(1)

    if not OPCODE_MAP:
        print("[!] OPCODE_MAP is empty — fill in the opcode definitions")
        sys.exit(1)

    # Parse bytecode
    instructions = parse_bytecode(BYTECODE, OPCODE_MAP)
    print(f"[+] Parsed {len(instructions)} instructions")
    for name, inst_args, pc in instructions:
        args_str = ", ".join(f"0x{a:x}" for a in inst_args) if inst_args else ""
        print(f"  {name} {args_str}")

    # Extract checkpoints
    checkpoints = trace_checkpoints(BYTECODE, OPCODE_MAP)
    print(f"\n[+] Found {len(checkpoints)} checkpoints")

    if args.forward and args.input:
        # Forward verification with given input
        input_bytes = list(bytes.fromhex(args.input))
        print(f"\n[+] Forward verification with input: {args.input}")
        ok = forward_execute(BYTECODE, OPCODE_MAP, input_bytes)
        print(f"\nResult: {'PASS' if ok else 'FAIL'}")
        return

    # Solve
    if args.z3:
        print("\n[+] Z3 solver...")
        key = z3_solve(checkpoints)
    elif args.brute:
        print("\n[+] Brute-force solver...")
        key = brute_solve(checkpoints)
    else:
        print("\n[+] Backward solver...")
        key = backward_solve(checkpoints)

    if key is None:
        print("[!] Solver failed")
        sys.exit(1)

    # Display result
    none_count = sum(1 for k in key if k is None)
    if none_count:
        print(f"\n[!] {none_count}/{len(key)} bytes unsolved")

    solved_bytes = bytes(k if k is not None else 0x3f for k in key)
    print(f"\n[+] Key bytes: {solved_bytes.hex()}")

    # Try as ASCII
    try:
        ascii_str = solved_bytes.decode("ascii")
        print(f"[+] Key ASCII: {ascii_str}")
    except UnicodeDecodeError:
        print(f"[+] Key (non-ASCII): {solved_bytes}")

    # Forward verification
    print(f"\n[+] Forward verification:")
    ok = forward_execute(BYTECODE, OPCODE_MAP, key)
    if ok:
        print("\n=== ALL CHECKS PASSED ===")
        print(f"FLAG input: {solved_bytes.hex()}")
    else:
        print("\n=== SOME CHECKS FAILED — review solution ===")


if __name__ == "__main__":
    main()
