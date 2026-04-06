#!/usr/bin/env python3
"""
gdb_pwn.py -- GDB batch helpers for pwn chain agent.

Replaces the "set break, run, x/16gx, continue, repeat" loop that eats 50%
of chain agent tokens. Every command emits a single GDB batch script via WSL
and returns structured output (JSON or compact text).

Subcommands:
  cyclic <bin> [--func vuln] [--size 256]
      Send pwntools cyclic pattern, run binary under GDB, on SIGSEGV report
      the BOF offset and faulting register/instruction.

  heap <bin> --bp <addr|sym>
      At the given breakpoint, dump tcache+fastbin+unsorted state via
      pwndbg/gef commands. Returns JSON describing each bin.

  trace-leak <bin> --bp <addr|sym> --reg <rdi|rsi|rdx|...>
      Break at addr, print register, also print 64 bytes around it.
      Useful to confirm what a leak primitive is actually leaking.

  inspect <bin> --bp <addr> [--bp <addr> ...] --regs --stack 32
      Multi-breakpoint single-shot inspection. One GDB run, one JSON out.

  canary <bin> --func <func>
      Locate stack canary read (mov rax, fs:0x28 / sub) and report offset
      from buffer start.

All subcommands take optional --input "AAAA" / --input-file path / --remote
HOST PORT for input plumbing.

Outputs are deliberately compact: JSON by default, with --pretty for humans.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent

GDB_PROLOGUE = """
set pagination off
set confirm off
set disable-randomization on
set print elements 0
"""


def to_wsl_path(p):
    s = str(Path(p).resolve())
    if len(s) >= 2 and s[1] == ":":
        return f"/mnt/{s[0].lower()}{s[2:].replace(chr(92), '/')}"
    return s.replace("\\", "/")


def run_gdb_batch(binary, gdb_script, stdin_bytes=None, timeout=60):
    """Run a GDB batch script via WSL. Returns combined stdout."""
    wsl_bin = to_wsl_path(binary)

    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(GDB_PROLOGUE + "\n" + gdb_script)
        gdb_path = f.name
    wsl_gdb_script = to_wsl_path(gdb_path)

    cmd = ["wsl", "--", "gdb", "-batch", "-x", wsl_gdb_script, wsl_bin]
    try:
        p = subprocess.run(
            cmd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
        )
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        err = (p.stderr or b"").decode("utf-8", errors="replace")
        return out + ("\n[stderr]\n" + err if err.strip() else "")
    finally:
        try:
            os.unlink(gdb_path)
        except OSError:
            pass


# ----------------------------------------------------------------------
# cyclic — find BOF offset
# ----------------------------------------------------------------------
def cmd_cyclic(args):
    """Send cyclic pattern, capture crash, compute offset."""
    try:
        from pwn import cyclic, cyclic_find
    except ImportError:
        print("[gdb_pwn] pwntools required: pip install pwntools", file=sys.stderr)
        sys.exit(1)

    pattern = cyclic(args.size)
    target = args.func or "main"

    script = f"""
break {target}
run
echo === ENTERED {target} ===\\n
continue
echo === CRASHED ===\\n
info registers rip rsp rbp rdi rsi rax
x/8gx $rsp
x/i $rip
"""
    out = run_gdb_batch(args.binary, script, stdin_bytes=pattern + b"\n")

    # Parse: find rip value, see if it matches a cyclic chunk
    result = {"crashed": False, "offset": None, "rip": None, "raw_excerpt": ""}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("rip"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    rip = int(parts[1], 16)
                    result["rip"] = hex(rip)
                    result["crashed"] = True
                    # Try cyclic match (last 8 bytes of rip as little-endian)
                    rip_bytes = rip.to_bytes(8, "little").rstrip(b"\x00")
                    if 4 <= len(rip_bytes) <= 8:
                        try:
                            off = cyclic_find(rip_bytes[:4])
                            if off >= 0:
                                result["offset"] = off
                        except Exception:
                            pass
                except ValueError:
                    pass

    # Also try to match $rsp top 8 bytes (for ret-overflow)
    if result["offset"] is None:
        for line in out.splitlines():
            if line.startswith("0x") and ":" in line:
                # x/8gx output
                hex_words = line.split(":")[1].split()
                for w in hex_words:
                    try:
                        v = int(w, 16)
                        b = v.to_bytes(8, "little").rstrip(b"\x00")
                        if 4 <= len(b) <= 8:
                            off = cyclic_find(b[:4])
                            if 0 <= off < args.size:
                                result["offset"] = off
                                break
                    except (ValueError, Exception):
                        continue
                if result["offset"] is not None:
                    break

    result["raw_excerpt"] = "\n".join(out.splitlines()[-15:])
    print(json.dumps(result, indent=2 if args.pretty else None))
    sys.exit(0 if result["offset"] is not None else 2)


# ----------------------------------------------------------------------
# heap — dump tcache/fastbin/unsorted at breakpoint
# ----------------------------------------------------------------------
def cmd_heap(args):
    """Stop at breakpoint and dump heap state. Tries pwndbg/gef commands."""
    bp = args.bp
    bp_cmd = f"break *{bp}" if bp.startswith("0x") else f"break {bp}"

    script = f"""
{bp_cmd}
run < /tmp/_gdb_pwn_input
echo === HEAP STATE ===\\n
heap chunks 2>/dev/null || echo "(no pwndbg heap chunks)"
echo === BINS ===\\n
bins 2>/dev/null || tcache 2>/dev/null || echo "(no bins/tcache cmd)"
echo === TCACHE ===\\n
tcachebins 2>/dev/null || echo "(no tcachebins)"
echo === FASTBINS ===\\n
fastbins 2>/dev/null || echo "(no fastbins)"
echo === UNSORTED ===\\n
unsortedbin 2>/dev/null || echo "(no unsortedbin)"
"""
    if args.input:
        stdin = args.input.encode() + b"\n"
    elif args.input_file:
        stdin = Path(args.input_file).read_bytes()
    else:
        stdin = b""

    # Write input to /tmp via wsl
    if stdin:
        subprocess.run(["wsl", "--", "bash", "-c", "cat > /tmp/_gdb_pwn_input"], input=stdin)
    else:
        subprocess.run(["wsl", "--", "bash", "-c", "echo > /tmp/_gdb_pwn_input"])

    out = run_gdb_batch(args.binary, script, timeout=args.timeout)

    # Compact: split sections
    sections = {}
    current = None
    for line in out.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current = line.strip("= ").lower().replace(" ", "_")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    result = {"breakpoint": bp, "sections": {k: "\n".join(v).strip() for k, v in sections.items()}}
    print(json.dumps(result, indent=2 if args.pretty else None))


# ----------------------------------------------------------------------
# trace-leak — observe register + memory at breakpoint
# ----------------------------------------------------------------------
def cmd_trace_leak(args):
    bp = args.bp
    reg = args.reg
    bp_cmd = f"break *{bp}" if bp.startswith("0x") else f"break {bp}"

    script = f"""
{bp_cmd}
run < /tmp/_gdb_pwn_input
echo === LEAK REG ===\\n
info registers {reg}
echo === MEM AT REG ===\\n
x/8gx ${reg}
echo === STRING AT REG ===\\n
x/s ${reg}
"""
    if args.input:
        subprocess.run(["wsl", "--", "bash", "-c", "cat > /tmp/_gdb_pwn_input"], input=args.input.encode() + b"\n")
    else:
        subprocess.run(["wsl", "--", "bash", "-c", "echo > /tmp/_gdb_pwn_input"])

    out = run_gdb_batch(args.binary, script, timeout=args.timeout)
    # Parse register value
    result = {"register": reg, "value": None, "mem_dump": "", "string": ""}
    in_mem, in_str = False, False
    mem_lines = []
    str_lines = []
    for line in out.splitlines():
        if line.startswith("=== MEM AT REG"):
            in_mem, in_str = True, False
            continue
        if line.startswith("=== STRING AT REG"):
            in_mem, in_str = False, True
            continue
        if line.startswith("==="):
            in_mem = in_str = False
            continue
        if line.strip().startswith(reg):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["value"] = hex(int(parts[1], 16))
                except ValueError:
                    pass
        elif in_mem:
            mem_lines.append(line)
        elif in_str:
            str_lines.append(line)
    result["mem_dump"] = "\n".join(mem_lines).strip()
    result["string"] = "\n".join(str_lines).strip()
    print(json.dumps(result, indent=2 if args.pretty else None))


# ----------------------------------------------------------------------
# inspect — multi-bp single-shot register/stack dump
# ----------------------------------------------------------------------
def cmd_inspect(args):
    bps = args.bp or []
    if not bps:
        print("[gdb_pwn] --bp required (one or more times)", file=sys.stderr)
        sys.exit(2)

    bp_section = "\n".join(f"break *{b}" if b.startswith("0x") else f"break {b}" for b in bps)

    cont_blocks = []
    for i, bp in enumerate(bps):
        block = f"""
echo === BP {i}: {bp} ===\\n
info registers rax rbx rcx rdx rdi rsi rsp rbp r8 r9 rip
x/{args.stack}gx $rsp
"""
        cont_blocks.append(block)
        if i < len(bps) - 1:
            cont_blocks.append("continue\n")

    script = bp_section + "\nrun < /tmp/_gdb_pwn_input\n" + "".join(cont_blocks) + "\n"

    if args.input:
        subprocess.run(["wsl", "--", "bash", "-c", "cat > /tmp/_gdb_pwn_input"], input=args.input.encode() + b"\n")
    else:
        subprocess.run(["wsl", "--", "bash", "-c", "echo > /tmp/_gdb_pwn_input"])

    out = run_gdb_batch(args.binary, script, timeout=args.timeout)

    sections = {}
    current = None
    for line in out.splitlines():
        if line.startswith("=== BP "):
            current = line.strip("= ")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    print(json.dumps({"breakpoints": bps, "dumps": {k: "\n".join(v).strip() for k, v in sections.items()}},
                     indent=2 if args.pretty else None))


# ----------------------------------------------------------------------
# canary — locate canary load + buffer offset
# ----------------------------------------------------------------------
def cmd_canary(args):
    """Disassemble func, find fs:0x28 load and stack-variable subtraction."""
    func = args.func or "main"
    script = f"""
disas {func}
"""
    out = run_gdb_batch(args.binary, script, timeout=args.timeout)
    result = {"function": func, "has_canary": False, "canary_load_addr": None, "buffer_size_hint": None}

    for line in out.splitlines():
        if "fs:0x28" in line or "%fs:0x28" in line:
            result["has_canary"] = True
            parts = line.strip().split()
            if parts and parts[0].startswith("0x"):
                result["canary_load_addr"] = parts[0].rstrip(":")
        # sub rsp, 0xNN
        if "sub " in line and "rsp" in line and "0x" in line:
            try:
                hexval = line.split("0x")[-1].split()[0].rstrip(",")
                result["buffer_size_hint"] = int(hexval, 16)
            except (ValueError, IndexError):
                pass

    print(json.dumps(result, indent=2 if args.pretty else None))


# ----------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pretty", action="store_true", help="indent JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("cyclic", help="find BOF offset via cyclic pattern")
    s.add_argument("binary")
    s.add_argument("--func", help="function to break on (default: main)")
    s.add_argument("--size", type=int, default=256)
    s.set_defaults(func=cmd_cyclic)

    s = sub.add_parser("heap", help="dump tcache/fastbin/unsorted at breakpoint")
    s.add_argument("binary")
    s.add_argument("--bp", required=True, help="breakpoint (0xADDR or symbol)")
    s.add_argument("--input", help="stdin input")
    s.add_argument("--input-file", help="stdin input file path")
    s.add_argument("--timeout", type=int, default=60)
    s.set_defaults(func=cmd_heap)

    s = sub.add_parser("trace-leak", help="observe register+memory at breakpoint")
    s.add_argument("binary")
    s.add_argument("--bp", required=True)
    s.add_argument("--reg", required=True, help="register to inspect (rdi/rsi/rax/...)")
    s.add_argument("--input", help="stdin input")
    s.add_argument("--timeout", type=int, default=60)
    s.set_defaults(func=cmd_trace_leak)

    s = sub.add_parser("inspect", help="multi-bp single-shot reg/stack dump")
    s.add_argument("binary")
    s.add_argument("--bp", action="append", help="breakpoint (repeatable)")
    s.add_argument("--stack", type=int, default=16, help="qwords to dump from rsp")
    s.add_argument("--input", help="stdin input")
    s.add_argument("--timeout", type=int, default=60)
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("canary", help="locate canary read + buffer size hint")
    s.add_argument("binary")
    s.add_argument("--func", default="main")
    s.add_argument("--timeout", type=int, default=30)
    s.set_defaults(func=cmd_canary)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
