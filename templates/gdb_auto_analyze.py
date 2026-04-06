#!/usr/bin/env python3
"""
GDB auto-analysis script generator for CTF reversing.

Generates GDB batch scripts that automatically:
1. Find comparison instructions (cmp, test) in validation functions
2. Set breakpoints and log register values
3. Run with sample input to observe behavior
4. Extract key values, offsets, and control flow

Usage:
  python templates/gdb_auto_analyze.py ./binary --func main
  python templates/gdb_auto_analyze.py ./binary --func validate --input "AAAA"
  python templates/gdb_auto_analyze.py ./binary --anti-debug  # detect anti-debug
  python templates/gdb_auto_analyze.py ./binary --oracle --charset printable --pos 0

Generates: gdb_script.gdb (run with: wsl gdb -batch -x gdb_script.gdb ./binary)
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path


def get_disasm(binary: str, func: str = "") -> str:
    """Get objdump disassembly."""
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        # Try WSL
        result = subprocess.run(
            ["wsl", "objdump", "-d", "-M", "intel", binary],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout


def find_cmp_instructions(disasm: str, func_name: str = "main") -> list[dict]:
    """Find comparison instructions in a function."""
    cmps = []
    in_func = False
    func_pattern = re.compile(rf'<{func_name}>:')

    for line in disasm.splitlines():
        if func_pattern.search(line):
            in_func = True
            continue
        if in_func and re.match(r'^$|^\S+ <', line) and not line.strip().startswith("0"):
            break
        if not in_func:
            continue

        # Match cmp/test instructions
        m = re.match(r'\s*([0-9a-f]+):\s+.*\b(cmp|test)\b\s+(.*)', line, re.I)
        if m:
            addr = m.group(1)
            insn = m.group(2)
            operands = m.group(3).strip()
            cmps.append({"addr": addr, "insn": insn, "operands": operands, "line": line.strip()})

    return cmps


def generate_breakpoint_script(binary: str, cmps: list[dict], input_str: str = "") -> str:
    """Generate GDB script that breaks at comparisons and logs values."""
    lines = [
        "# Auto-generated GDB analysis script",
        f"# Binary: {binary}",
        "set pagination off",
        "set confirm off",
        "set logging enabled on",
        "set logging file gdb_analysis.log",
        "set logging overwrite on",
        "",
    ]

    for i, cmp in enumerate(cmps):
        addr = cmp["addr"]
        lines.append(f"# CMP #{i}: {cmp['line']}")
        lines.append(f"break *0x{addr}")
        lines.append("commands")
        lines.append("  silent")
        lines.append(f'  printf "CMP #{i} at 0x{addr}: "')
        # Log relevant registers based on operands
        regs = _extract_regs(cmp["operands"])
        for reg in regs:
            lines.append(f'  printf "{reg}=0x%x ", ${reg}')
        lines.append('  printf "\\n"')
        lines.append("  continue")
        lines.append("end")
        lines.append("")

    # Run with input
    if input_str:
        lines.append(f'run <<< "{input_str}"')
    else:
        lines.append("run")

    lines.append("")
    lines.append("quit")
    return "\n".join(lines)


def generate_anti_debug_detect(binary: str) -> str:
    """Generate GDB script that detects anti-debug techniques."""
    return f"""# Anti-debug detection script
# Binary: {binary}
set pagination off
set confirm off

# 1. Check for ptrace calls
catch syscall ptrace
commands
  silent
  printf "ANTI-DEBUG: ptrace syscall detected at "
  bt 1
  # Override ptrace to return 0 (bypass)
  set $rax = 0
  continue
end

# 2. Check for time-based anti-debug
catch syscall clock_gettime
catch syscall gettimeofday
commands
  silent
  printf "ANTI-DEBUG: timing check detected\\n"
  continue
end

# 3. Break on common anti-debug functions
break alarm
commands
  silent
  printf "ANTI-DEBUG: alarm() called with %d seconds\\n", $rdi
  set $rdi = 0
  continue
end

break signal
commands
  silent
  printf "ANTI-DEBUG: signal() called, sig=%d\\n", $rdi
  continue
end

# 4. Check /proc/self/status for TracerPid
break fopen
commands
  silent
  if $_streq((char*)$rdi, "/proc/self/status")
    printf "ANTI-DEBUG: reading /proc/self/status (TracerPid check)\\n"
  end
  continue
end

run
quit
"""


def generate_byte_oracle(binary: str, flag_len: int = 32, charset: str = "printable",
                         known_prefix: str = "") -> str:
    """Generate GDB script for byte-by-byte oracle attack.

    Uses instruction counting: the correct byte makes the program execute
    more instructions before failing.
    """
    if charset == "printable":
        chars = "".join(chr(c) for c in range(0x20, 0x7f))
    elif charset == "alnum":
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    elif charset == "hex":
        chars = "0123456789abcdef"
    else:
        chars = charset

    return f"""#!/usr/bin/env python3
\"\"\"Byte-by-byte oracle solver using instruction counting.
Run: wsl python3 gdb_oracle.py ./{binary}
\"\"\"
import subprocess
import string

BINARY = "./{binary}"
FLAG_LEN = {flag_len}
KNOWN = "{known_prefix}"
CHARSET = "{chars}"

def count_instructions(candidate: str) -> int:
    \"\"\"Run binary with candidate input, count instructions via perf.\"\"\"
    try:
        # Method 1: perf stat (most accurate)
        result = subprocess.run(
            ["perf", "stat", "-e", "instructions:u", "-x", ",", BINARY],
            input=candidate + "\\n",
            capture_output=True, text=True, timeout=5
        )
        for line in result.stderr.splitlines():
            if "instructions" in line:
                return int(line.split(",")[0])
    except Exception:
        pass

    # Method 2: GDB with step counting (slower but portable)
    gdb_script = f'''
set pagination off
set confirm off
break main
run <<< "{candidate}"
set $count = 0
while 1
  si
  set $count = $count + 1
end
'''
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-ex", gdb_script, BINARY],
            capture_output=True, text=True, timeout=10
        )
        # Count lines of execution
        return len(result.stdout.splitlines())
    except Exception:
        return 0


def solve():
    flag = list(KNOWN)
    for pos in range(len(KNOWN), FLAG_LEN):
        best_char = None
        best_count = -1
        for c in CHARSET:
            candidate = "".join(flag) + c + "A" * (FLAG_LEN - pos - 1)
            count = count_instructions(candidate)
            if count > best_count:
                best_count = count
                best_char = c
        flag.append(best_char)
        print(f"[{{pos:2d}}] '{{best_char}}' ({{best_count}} insns) -> {{''.join(flag)}}")

    print(f"FLAG: {{''.join(flag)}}")

if __name__ == "__main__":
    solve()
"""


def generate_ld_preload_bypass(functions: list[str]) -> str:
    """Generate LD_PRELOAD C source to bypass anti-debug functions."""
    lines = [
        "// Anti-debug bypass via LD_PRELOAD",
        "// Compile: gcc -shared -fPIC -o bypass.so bypass.c",
        "// Usage:   LD_PRELOAD=./bypass.so ./binary",
        "#include <time.h>",
        "#include <sys/ptrace.h>",
        "#include <signal.h>",
        "#include <stdio.h>",
        "",
    ]

    if "ptrace" in functions:
        lines.extend([
            "long ptrace(int request, ...) {",
            '    // fprintf(stderr, "[bypass] ptrace(%d) -> 0\\n", request);',
            "    return 0;",
            "}",
            "",
        ])

    if "time" in functions:
        lines.extend([
            "time_t time(time_t *t) {",
            "    time_t v = 1700000000;  // Fixed timestamp",
            "    if (t) *t = v;",
            "    return v;",
            "}",
            "",
        ])

    if "alarm" in functions:
        lines.extend([
            "unsigned int alarm(unsigned int seconds) {",
            '    // fprintf(stderr, "[bypass] alarm(%u) -> disabled\\n", seconds);',
            "    return 0;",
            "}",
            "",
        ])

    if "clock_gettime" in functions:
        lines.extend([
            "int clock_gettime(clockid_t clk_id, struct timespec *tp) {",
            "    tp->tv_sec = 1700000000;",
            "    tp->tv_nsec = 0;",
            "    return 0;",
            "}",
            "",
        ])

    if "signal" in functions:
        lines.extend([
            "typedef void (*sighandler_t)(int);",
            "sighandler_t signal(int signum, sighandler_t handler) {",
            '    // fprintf(stderr, "[bypass] signal(%d) -> ignored\\n", signum);',
            "    return handler;",
            "}",
            "",
        ])

    return "\n".join(lines)


def _extract_regs(operands: str) -> list[str]:
    """Extract register names from operand string."""
    regs = set()
    for r in re.findall(r'\b(e?[abcd]x|e?[sd]i|e?[sb]p|r[0-9]+[dwb]?|r[abcd]x|r[sd]i|r[sb]p|[abcd]l|[abcd]h)\b', operands, re.I):
        regs.add(r.lower())
    # Always include rax and common comparison registers
    if not regs:
        regs = {"rax", "rbx", "rcx", "rdx"}
    return sorted(regs)


def main():
    parser = argparse.ArgumentParser(description="GDB auto-analysis script generator")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--func", default="main", help="Function to analyze")
    parser.add_argument("--input", default="", help="Sample input string")
    parser.add_argument("--anti-debug", action="store_true", help="Generate anti-debug detection script")
    parser.add_argument("--oracle", action="store_true", help="Generate byte-by-byte oracle solver")
    parser.add_argument("--charset", default="printable", help="Charset for oracle (printable/alnum/hex)")
    parser.add_argument("--len", type=int, default=32, help="Flag length for oracle")
    parser.add_argument("--prefix", default="", help="Known flag prefix")
    parser.add_argument("--bypass", nargs="*", help="Generate LD_PRELOAD bypass (ptrace,time,alarm,signal)")
    parser.add_argument("-o", "--output", default="", help="Output file")
    args = parser.parse_args()

    binary = args.binary

    if args.anti_debug:
        script = generate_anti_debug_detect(binary)
        out_file = args.output or "gdb_anti_debug.gdb"
        Path(out_file).write_text(script)
        print(f"[+] Anti-debug detection script: {out_file}")
        print(f"    Run: wsl gdb -batch -x {out_file} ./{binary}")

    elif args.oracle:
        script = generate_byte_oracle(binary, args.len, args.charset, args.prefix)
        out_file = args.output or "gdb_oracle.py"
        Path(out_file).write_text(script)
        print(f"[+] Byte oracle solver: {out_file}")
        print(f"    Run: wsl python3 {out_file}")

    elif args.bypass:
        script = generate_ld_preload_bypass(args.bypass)
        out_file = args.output or "bypass.c"
        Path(out_file).write_text(script)
        print(f"[+] LD_PRELOAD bypass: {out_file}")
        print(f"    Compile: wsl gcc -shared -fPIC -o bypass.so {out_file}")
        print(f"    Usage:   wsl LD_PRELOAD=./bypass.so ./{binary}")

    else:
        disasm = get_disasm(binary)
        cmps = find_cmp_instructions(disasm, args.func)
        print(f"[+] Found {len(cmps)} comparison instructions in {args.func}:")
        for i, c in enumerate(cmps):
            print(f"    #{i}: {c['line']}")

        script = generate_breakpoint_script(binary, cmps, args.input)
        out_file = args.output or "gdb_script.gdb"
        Path(out_file).write_text(script)
        print(f"\n[+] GDB script written to: {out_file}")
        print(f"    Run: wsl gdb -batch -x {out_file} ./{binary}")


if __name__ == "__main__":
    main()
