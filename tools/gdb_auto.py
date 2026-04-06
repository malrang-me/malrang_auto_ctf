#!/usr/bin/env python3
"""
Anti-debug detection, bypass, and binary patching tool.

Subcommands:
  detect  — Static analysis for anti-debug techniques (imports/strings/patterns)
  bypass  — Generate LD_PRELOAD bypass.c source
  patch   — Binary-patch anti-debug calls to NOP
  script  — Generate GDB scripts (anti-debug detect, cmp breakpoints, byte oracle)

Usage:
  python tools/gdb_auto.py detect ./binary [--ida]
  python tools/gdb_auto.py bypass ./binary -o bypass.c
  python tools/gdb_auto.py patch  ./binary -o patched
  python tools/gdb_auto.py script ./binary --anti-debug
  python tools/gdb_auto.py script ./binary --oracle --charset printable --len 32
  python tools/gdb_auto.py script ./binary --func main --input "AAAA"
"""

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run command, try native then WSL fallback."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # WSL fallback
    try:
        r = subprocess.run(["wsl"] + cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _wsl_path(path: str) -> str:
    """Convert Windows path to WSL path."""
    p = Path(path).resolve()
    s = str(p).replace("\\", "/")
    m = re.match(r"([A-Za-z]):/(.+)", s)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return s


def _check_ida_available() -> bool:
    """Check if IDA MCP RPC is responding (same pattern as ida_auto.py)."""
    import urllib.request
    try:
        payload = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:13337",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DETECT — Static anti-debug detection
# ---------------------------------------------------------------------------

ANTI_DEBUG_IMPORTS = {
    "ptrace": "ptrace syscall - anti-debug via PTRACE_TRACEME",
    "alarm": "alarm() - kill process after timeout (anti-debug timer)",
    "signal": "signal() - custom signal handler (SIGTRAP trap, SIGALRM kill)",
    "clock_gettime": "clock_gettime - timing-based anti-debug",
    "gettimeofday": "gettimeofday - timing-based anti-debug",
    "getauxval": "getauxval - environment fingerprint / opaque predicate",
    "prctl": "prctl - PR_SET_DUMPABLE or PR_SET_PTRACER",
    "dlopen": "dlopen - dynamic library loading (import obfuscation)",
    "dlsym": "dlsym - dynamic symbol resolution (import obfuscation)",
}

ANTI_DEBUG_STRINGS = {
    "/proc/self/status": "TracerPid check via /proc/self/status",
    "/proc/self/maps": "/proc/self/maps check for breakpoints",
    "TracerPid": "Direct TracerPid string reference",
    "IsDebuggerPresent": "Windows API anti-debug",
    "NtQueryInformationProcess": "Windows NT anti-debug",
    "PTRACE_TRACEME": "ptrace anti-debug constant reference",
    "BeingDebugged": "PEB.BeingDebugged check",
}


def detect(binary_path: str, use_ida: bool = False) -> dict:
    """Static analysis for anti-debug techniques. Returns detection dict."""
    result = {
        "binary": binary_path,
        "detections": {},
        "imports_found": [],
        "strings_found": [],
        "summary": [],
    }

    wsl_bin = _wsl_path(binary_path)

    # 1. Check dynamic symbols / imports
    dynsym = _run(["readelf", "-d", "--wide", wsl_bin])
    dynsym += "\n" + _run(["readelf", "--dyn-syms", "--wide", wsl_bin])
    objdump_plt = _run(["objdump", "-d", "-j", ".plt", "-j", ".plt.got", "-M", "intel", wsl_bin])

    for func, desc in ANTI_DEBUG_IMPORTS.items():
        found = False
        # Check in dynamic symbols
        if re.search(rf'\b{func}\b', dynsym, re.I):
            found = True
        # Check in PLT
        if re.search(rf'<{func}@plt>', objdump_plt, re.I):
            found = True
        if found:
            result["detections"][func] = desc
            result["imports_found"].append(func)

    # 2. Check strings for anti-debug indicators
    strings_out = _run(["strings", wsl_bin])
    for pattern, desc in ANTI_DEBUG_STRINGS.items():
        if pattern.lower() in strings_out.lower():
            result["detections"][f"str_{pattern}"] = desc
            result["strings_found"].append(pattern)

    # 3. Check for int3 (0xCC) breakpoint traps in .text
    text_section = _run(["objdump", "-d", "-j", ".text", "-M", "intel", wsl_bin])
    int3_count = len(re.findall(r'\bint3\b', text_section, re.I))
    if int3_count > 3:  # A few int3 are normal (alignment), many = anti-debug
        result["detections"]["int3_trap"] = f"int3 breakpoint traps detected ({int3_count} instances)"

    # 4. Check for syscall-based ptrace (bypass PLT)
    if re.search(r'mov\s+.*,\s*0x65\b.*syscall|mov\s+.*,\s*101\b.*syscall', text_section, re.I):
        result["detections"]["ptrace_syscall"] = "Direct ptrace syscall (bypasses PLT)"

    # 5. IDA-enhanced detection (optional)
    if use_ida and _check_ida_available():
        result["ida_enhanced"] = True
        # IDA detection happens via MCP tools in the agent — we just flag availability
    else:
        result["ida_enhanced"] = False

    # Build summary
    if "ptrace" in result["detections"] or "ptrace_syscall" in result["detections"]:
        result["summary"].append("PTRACE")
    if any(k in result["detections"] for k in ["clock_gettime", "gettimeofday"]):
        result["summary"].append("TIMING")
    if "alarm" in result["detections"]:
        result["summary"].append("ALARM")
    if "signal" in result["detections"]:
        result["summary"].append("SIGNAL")
    if any("TracerPid" in k or "/proc/self/status" in k for k in result["detections"]):
        result["summary"].append("TRACERPID")
    if "getauxval" in result["detections"]:
        result["summary"].append("GETAUXVAL")
    if "int3_trap" in result["detections"]:
        result["summary"].append("INT3_TRAP")
    if any(k in result["detections"] for k in ["dlopen", "dlsym"]):
        result["summary"].append("IMPORT_OBFUSC")

    result["has_anti_debug"] = len(result["summary"]) > 0
    result["recommended_bypass"] = _recommend_bypass(result["summary"])

    return result


def _recommend_bypass(summary: list[str]) -> list[str]:
    """Recommend bypass strategies based on detected techniques."""
    recs = []
    if not summary:
        return ["none_needed"]

    bypass_funcs = []
    if "PTRACE" in summary:
        bypass_funcs.append("ptrace")
    if "TIMING" in summary:
        bypass_funcs.extend(["clock_gettime", "time"])
    if "ALARM" in summary:
        bypass_funcs.append("alarm")
    if "SIGNAL" in summary:
        bypass_funcs.append("signal")
    if "TRACERPID" in summary:
        bypass_funcs.append("fopen")
    if "GETAUXVAL" in summary:
        bypass_funcs.append("getauxval")

    if bypass_funcs:
        recs.append(f"ld_preload: {','.join(bypass_funcs)}")
        recs.append("binary_patch: NOP anti-debug calls")
        recs.append("gdb_override: set $rax=0 at check points")

    if "INT3_TRAP" in summary:
        recs.append("gdb: handle SIGTRAP nostop noprint")

    if "IMPORT_OBFUSC" in summary:
        recs.append("gdb: break dlsym, log resolved symbols")

    return recs


# ---------------------------------------------------------------------------
# BYPASS — Generate LD_PRELOAD C source
# ---------------------------------------------------------------------------

BYPASS_TEMPLATES = {
    "ptrace": '''
long ptrace(int request, ...) {
    return 0;  /* Always succeed, bypass PTRACE_TRACEME */
}
''',
    "time": '''
#include <time.h>
time_t time(time_t *t) {
    time_t v = 1700000000;
    if (t) *t = v;
    return v;
}
''',
    "alarm": '''
unsigned int alarm(unsigned int seconds) {
    return 0;  /* Disable all alarms */
}
''',
    "clock_gettime": '''
int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    tp->tv_sec = 1700000000;
    tp->tv_nsec = 0;
    return 0;
}
''',
    "gettimeofday": '''
#include <sys/time.h>
int gettimeofday(struct timeval *tv, void *tz) {
    tv->tv_sec = 1700000000;
    tv->tv_usec = 0;
    return 0;
}
''',
    "signal": '''
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler) {
    return handler;  /* Ignore all signal registrations */
}
''',
    "getauxval": '''
unsigned long getauxval(unsigned long type) {
    if (type == 6) return 0x1000;  /* AT_HWCAP: return power of 2 */
    if (type == 26) return 0;      /* AT_HWCAP2: return 0 */
    return 0;
}
''',
    "fopen": '''
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
FILE *fopen(const char *path, const char *mode) {
    /* Block /proc/self/status reads (TracerPid bypass) */
    if (strstr(path, "/proc/self/status") || strstr(path, "/proc/self/maps")) {
        /* Return /dev/null — TracerPid will show 0 */
        static FILE *(*real_fopen)(const char*, const char*) = NULL;
        if (!real_fopen) real_fopen = dlsym((void*)-1, "fopen");
        return real_fopen("/dev/null", mode);
    }
    static FILE *(*real_fopen)(const char*, const char*) = NULL;
    if (!real_fopen) real_fopen = dlsym((void*)-1, "fopen");
    return real_fopen(path, mode);
}
''',
    "prctl": '''
#include <sys/prctl.h>
int prctl(int option, ...) {
    return 0;  /* Allow all prctl operations */
}
''',
}


def generate_bypass(binary_path: str, functions: list[str] | None = None) -> str:
    """Generate LD_PRELOAD bypass.c for detected anti-debug functions."""
    if functions is None:
        # Auto-detect
        det = detect(binary_path)
        functions = det["imports_found"]
        # Add inferred functions from summary
        if "TRACERPID" in det["summary"]:
            functions.append("fopen")
        if "TIMING" in det["summary"] and "clock_gettime" not in functions:
            functions.append("clock_gettime")

    lines = [
        "// Auto-generated anti-debug bypass via LD_PRELOAD",
        f"// Binary: {binary_path}",
        "// Compile: gcc -shared -fPIC -ldl -o bypass.so bypass.c",
        "// Usage:   LD_PRELOAD=./bypass.so ./binary",
        "",
        "#define _GNU_SOURCE",
        "#include <time.h>",
        "#include <sys/ptrace.h>",
        "#include <signal.h>",
        "#include <stdio.h>",
        "#include <unistd.h>",
        "",
    ]

    added = set()
    for func in functions:
        key = func.lower()
        if key in BYPASS_TEMPLATES and key not in added:
            lines.append(BYPASS_TEMPLATES[key])
            added.add(key)

    if not added:
        lines.append("// No anti-debug functions detected — bypass not needed")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PATCH — Binary-patch anti-debug calls to NOP
# ---------------------------------------------------------------------------

def patch_binary(binary_path: str, output_path: str | None = None) -> dict:
    """Find and NOP anti-debug call instructions in the binary."""
    wsl_bin = _wsl_path(binary_path)
    result = {"patches": [], "total_patched": 0}

    # Get disassembly to find anti-debug call sites
    disasm = _run(["objdump", "-d", "-M", "intel", wsl_bin])

    # Patterns to patch: call <anti_debug_func>@plt
    anti_funcs = ["ptrace", "alarm", "signal", "clock_gettime", "gettimeofday", "getauxval", "prctl"]
    patch_sites = []

    for line in disasm.splitlines():
        for func in anti_funcs:
            if re.search(rf'call\s+.*<{func}@plt>', line, re.I):
                m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s+call', line, re.I)
                if m:
                    addr = int(m.group(1), 16)
                    insn_bytes = bytes.fromhex(m.group(2).replace(" ", ""))
                    insn_len = len(insn_bytes)
                    patch_sites.append({
                        "addr": addr,
                        "func": func,
                        "len": insn_len,
                        "original": insn_bytes.hex(),
                        "line": line.strip(),
                    })

    if not patch_sites:
        result["message"] = "No anti-debug call sites found for patching"
        print(json.dumps(result, indent=2))
        return result

    # Find file offset for each virtual address
    # Parse section headers to get VA → file offset mapping
    sections = _run(["readelf", "-S", "--wide", wsl_bin])
    section_map = []
    for line in sections.splitlines():
        m = re.search(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line, re.I)
        if m:
            section_map.append({
                "name": m.group(1),
                "vaddr": int(m.group(2), 16),
                "offset": int(m.group(3), 16),
                "size": int(m.group(4), 16),
            })

    def va_to_offset(va: int) -> int | None:
        for s in section_map:
            if s["vaddr"] <= va < s["vaddr"] + s["size"]:
                return s["offset"] + (va - s["vaddr"])
        return None

    # Read binary and apply patches
    data = bytearray(Path(binary_path).read_bytes())
    for site in patch_sites:
        file_off = va_to_offset(site["addr"])
        if file_off is None:
            site["status"] = "skip_no_offset"
            continue

        # Replace call instruction with NOPs (0x90)
        nop_bytes = b"\x90" * site["len"]
        # For ptrace: we want it to return 0, so use: xor eax,eax; nop...
        if site["func"] == "ptrace" and site["len"] >= 2:
            nop_bytes = b"\x31\xc0" + b"\x90" * (site["len"] - 2)  # xor eax,eax + NOPs

        data[file_off:file_off + site["len"]] = nop_bytes
        site["file_offset"] = hex(file_off)
        site["patched"] = nop_bytes.hex()
        site["status"] = "patched"
        result["total_patched"] += 1

    result["patches"] = patch_sites

    # Write patched binary
    out = output_path or (binary_path + ".patched")
    Path(out).write_bytes(bytes(data))
    # Make executable
    try:
        import os
        os.chmod(out, 0o755)
    except Exception:
        _run(["chmod", "+x", _wsl_path(out)])

    result["output"] = out
    return result


# ---------------------------------------------------------------------------
# SCRIPT — GDB script generation (preserved from templates/gdb_auto_analyze.py)
# ---------------------------------------------------------------------------

def generate_anti_debug_script(binary: str) -> str:
    """Generate GDB script for anti-debug detection + bypass."""
    return f"""# Anti-debug detection + bypass script
# Binary: {binary}
# Run: wsl gdb -batch -x gdb_anti_debug.gdb ./{binary}
set pagination off
set confirm off

# Ptrace bypass
catch syscall ptrace
commands
  silent
  printf "ANTI-DEBUG: ptrace syscall detected at "
  bt 1
  set $rax = 0
  continue
end

# Timing bypass
catch syscall clock_gettime
catch syscall gettimeofday
commands
  silent
  printf "ANTI-DEBUG: timing check detected\\n"
  continue
end

# Alarm bypass
break alarm
commands
  silent
  printf "ANTI-DEBUG: alarm(%d) -> disabled\\n", $rdi
  set $rdi = 0
  continue
end

# Signal monitoring
break signal
commands
  silent
  printf "ANTI-DEBUG: signal(%d) registered\\n", $rdi
  continue
end

# TracerPid check bypass
break fopen
commands
  silent
  if $_streq((char*)$rdi, "/proc/self/status")
    printf "ANTI-DEBUG: TracerPid check via /proc/self/status\\n"
  end
  if $_streq((char*)$rdi, "/proc/self/maps")
    printf "ANTI-DEBUG: /proc/self/maps check\\n"
  end
  continue
end

# SIGTRAP handler (int3 traps)
handle SIGTRAP nostop noprint pass

run
quit
"""


def generate_cmp_script(binary: str, func: str = "main", input_str: str = "") -> str:
    """Generate GDB script for breakpoints at comparison instructions."""
    wsl_bin = _wsl_path(binary)
    disasm = _run(["objdump", "-d", "-M", "intel", wsl_bin])

    cmps = []
    in_func = False
    for line in disasm.splitlines():
        if re.search(rf'<{func}>:', line):
            in_func = True
            continue
        if in_func and re.match(r'^$|^\S+ <', line) and not line.strip().startswith("0"):
            break
        if not in_func:
            continue
        m = re.match(r'\s*([0-9a-f]+):\s+.*\b(cmp|test)\b\s+(.*)', line, re.I)
        if m:
            cmps.append({"addr": m.group(1), "insn": m.group(2), "operands": m.group(3).strip()})

    lines = [
        f"# Auto-generated CMP breakpoint script for {func}",
        f"# Found {len(cmps)} comparison instructions",
        "set pagination off", "set confirm off",
        "set logging enabled on", "set logging file gdb_analysis.log",
        "set logging overwrite on", "",
    ]

    for i, cmp in enumerate(cmps):
        lines.append(f"break *0x{cmp['addr']}")
        lines.append("commands")
        lines.append("  silent")
        lines.append(f'  printf "CMP #{i} at 0x{cmp["addr"]}: "')
        regs = _extract_regs(cmp["operands"])
        for reg in regs:
            lines.append(f'  printf "{reg}=0x%x ", ${reg}')
        lines.append('  printf "\\n"')
        lines.append("  continue")
        lines.append("end\n")

    lines.append(f'run <<< "{input_str}"' if input_str else "run")
    lines.append("quit")
    return "\n".join(lines)


def generate_oracle_script(binary: str, flag_len: int = 32,
                           charset: str = "printable", prefix: str = "") -> str:
    """Generate byte-by-byte oracle solver using instruction counting."""
    if charset == "printable":
        chars = "".join(chr(c) for c in range(0x20, 0x7f))
    elif charset == "alnum":
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    elif charset == "hex":
        chars = "0123456789abcdef"
    else:
        chars = charset

    return f'''#!/usr/bin/env python3
"""Byte-by-byte oracle solver using instruction counting.
Run: wsl python3 gdb_oracle.py
"""
import subprocess

BINARY = "./{binary}"
FLAG_LEN = {flag_len}
KNOWN = "{prefix}"
CHARSET = "{chars}"

def count_instructions(candidate: str) -> int:
    """Count executed instructions via perf stat."""
    try:
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
    return 0

def solve():
    flag = list(KNOWN)
    for pos in range(len(KNOWN), FLAG_LEN):
        best_char, best_count = None, -1
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
'''


def _extract_regs(operands: str) -> list[str]:
    """Extract register names from operand string."""
    regs = set()
    for r in re.findall(
        r'\b(e?[abcd]x|e?[sd]i|e?[sb]p|r[0-9]+[dwb]?|r[abcd]x|r[sd]i|r[sb]p|[abcd][lh])\b',
        operands, re.I
    ):
        regs.add(r.lower())
    return sorted(regs) or ["rax", "rbx", "rcx", "rdx"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_detect(args):
    result = detect(args.binary, use_ida=args.ida)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_bypass(args):
    funcs = args.functions.split(",") if args.functions else None
    src = generate_bypass(args.binary, funcs)
    out = args.output or "bypass.c"
    Path(out).write_text(src)
    print(f"[+] LD_PRELOAD bypass: {out}")
    print(f"    Compile: wsl gcc -shared -fPIC -ldl -o bypass.so {out}")
    wsl_bin = Path(args.binary).name
    print(f"    Usage:   wsl LD_PRELOAD=./bypass.so ./{wsl_bin}")


def cmd_patch(args):
    result = patch_binary(args.binary, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_script(args):
    binary = args.binary

    if args.anti_debug:
        script = generate_anti_debug_script(binary)
        out = args.output or "gdb_anti_debug.gdb"
        Path(out).write_text(script)
        print(f"[+] Anti-debug script: {out}")
        print(f"    Run: wsl gdb -batch -x {out} ./{binary}")

    elif args.oracle:
        script = generate_oracle_script(binary, args.len, args.charset, args.prefix)
        out = args.output or "gdb_oracle.py"
        Path(out).write_text(script)
        print(f"[+] Oracle solver: {out}")
        print(f"    Run: wsl python3 {out}")

    else:
        script = generate_cmp_script(binary, args.func, args.input)
        out = args.output or "gdb_script.gdb"
        Path(out).write_text(script)
        print(f"[+] CMP breakpoint script: {out}")
        print(f"    Run: wsl gdb -batch -x {out} ./{binary}")


def main():
    p = argparse.ArgumentParser(description="Anti-debug detection, bypass, and patching tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    # detect
    s = sub.add_parser("detect", help="Detect anti-debug techniques in binary")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--ida", action="store_true", help="Use IDA MCP for enhanced detection")

    # bypass
    s = sub.add_parser("bypass", help="Generate LD_PRELOAD bypass.c")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--functions", "-f", default=None, help="Comma-separated functions to bypass (auto-detect if omitted)")
    s.add_argument("-o", "--output", default=None, help="Output file path")

    # patch
    s = sub.add_parser("patch", help="Binary-patch anti-debug calls to NOP")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("-o", "--output", default=None, help="Output patched binary path")

    # script
    s = sub.add_parser("script", help="Generate GDB scripts")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--anti-debug", action="store_true", help="Anti-debug detection script")
    s.add_argument("--oracle", action="store_true", help="Byte-by-byte oracle solver")
    s.add_argument("--func", default="main", help="Function for CMP breakpoints")
    s.add_argument("--input", default="", help="Sample input")
    s.add_argument("--charset", default="printable", help="Charset for oracle")
    s.add_argument("--len", type=int, default=32, help="Flag length for oracle")
    s.add_argument("--prefix", default="", help="Known flag prefix")
    s.add_argument("-o", "--output", default=None, help="Output file path")

    args = p.parse_args()
    dispatch = {"detect": cmd_detect, "bypass": cmd_bypass, "patch": cmd_patch, "script": cmd_script}
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
