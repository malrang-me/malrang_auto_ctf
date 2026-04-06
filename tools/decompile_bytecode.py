#!/usr/bin/env python3
"""
Bytecode decompiler chain for CTF reversing.

Supports Python (.pyc), Java (.class/.jar), .NET (.exe/.dll), WebAssembly (.wasm).
Auto-detects file type and applies the best available decompiler.

Usage:
  python tools/decompile_bytecode.py detect file.pyc
  python tools/decompile_bytecode.py decompile file.pyc -o source.py
  python tools/decompile_bytecode.py decompile app.jar -o output_dir/
  python tools/decompile_bytecode.py decompile program.exe -o output_dir/  # .NET
  python tools/decompile_bytecode.py decompile module.wasm -o module.wat

All tools run via WSL. Install decompilers as needed.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ============================================================================
# File Type Detection
# ============================================================================

MAGIC_BYTES = {
    b"\x42\x0d\x0d\x0a": "python_pyc",      # Python 3.x magic (varies by version)
    b"\xe3\x00\x00\x00": "python_pyc_27",    # Python 2.7
    b"\xca\xfe\xba\xbe": "java_class",       # Java class file
    b"\x50\x4b\x03\x04": "zip_archive",      # ZIP (could be JAR/APK)
    b"\x4d\x5a": "pe_executable",            # PE (could be .NET)
    b"\x00\x61\x73\x6d": "wasm",             # WebAssembly
}

# Python magic -> version mapping (first 2 bytes of .pyc)
PYTHON_MAGIC = {
    3394: "3.8", 3401: "3.8", 3413: "3.9", 3425: "3.10",
    3433: "3.10", 3438: "3.11", 3450: "3.11", 3495: "3.12",
    3531: "3.13",
}


def detect_file_type(file_path: str) -> dict:
    """Detect bytecode file type from magic bytes and extension."""
    result = {"file": file_path, "type": "unknown", "details": {}}
    path = Path(file_path)
    ext = path.suffix.lower()

    with open(file_path, "rb") as f:
        header = f.read(16)

    # Extension-based hints
    if ext == ".pyc" or ext == ".pyo":
        result["type"] = "python"
        magic = int.from_bytes(header[:2], "little")
        result["details"]["magic"] = magic
        result["details"]["python_version"] = PYTHON_MAGIC.get(magic, f"unknown (magic={magic})")
    elif ext == ".class":
        result["type"] = "java"
    elif ext == ".jar":
        result["type"] = "java_jar"
    elif ext == ".wasm":
        result["type"] = "wasm"
    elif ext in (".exe", ".dll"):
        # Check if .NET (PE with CLI header)
        if header[:2] == b"\x4d\x5a":
            result["type"] = "pe"
            # Quick check for .NET: look for "mscoree.dll" in first 4KB
            with open(file_path, "rb") as f:
                chunk = f.read(4096)
            if b"mscoree.dll" in chunk or b"_CorExeMain" in chunk:
                result["type"] = "dotnet"
                result["details"]["runtime"] = ".NET"
            else:
                result["type"] = "native_pe"
    elif ext == ".apk":
        result["type"] = "android_apk"
    else:
        # Magic-based detection
        for magic, ftype in MAGIC_BYTES.items():
            if header[:len(magic)] == magic:
                if ftype == "zip_archive":
                    # Check if JAR (contains META-INF/MANIFEST.MF)
                    result["type"] = "java_jar"  # assume JAR for CTF
                else:
                    result["type"] = ftype
                break

    return result


# ============================================================================
# Decompiler Chains
# ============================================================================

def _run_wsl(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run command via WSL, return (stdout, stderr, returncode)."""
    full_cmd = ["wsl"] + cmd if sys.platform == "win32" else cmd
    try:
        r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2


def _wsl_path(path: str) -> str:
    """Convert Windows path to WSL path."""
    p = Path(path).resolve()
    s = str(p).replace("\\", "/")
    m = re.match(r"([A-Za-z]):/(.+)", s)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return s


# ── Python ─────────────────────────────────────────────────────────────

def decompile_python(file_path: str, output: str = None) -> dict:
    """Decompile Python .pyc file. Tries decompilers in order."""
    wsl_file = _wsl_path(file_path)
    out_file = output or str(Path(file_path).with_suffix(".py"))
    result = {"file": file_path, "tool": None, "output": out_file, "success": False}

    decompilers = [
        ("uncompyle6", ["uncompyle6", wsl_file]),
        ("decompile3", ["decompile3", wsl_file]),
        ("pycdc", ["pycdc", wsl_file]),
        ("dis_fallback", ["python3", "-m", "dis", wsl_file]),
    ]

    for name, cmd in decompilers:
        stdout, stderr, rc = _run_wsl(cmd, timeout=30)
        if rc == 0 and stdout.strip():
            result["tool"] = name
            result["success"] = True

            # Write output
            wsl_out = _wsl_path(out_file)
            Path(out_file).write_text(stdout, encoding="utf-8")

            lines = stdout.count("\n")
            print(f"[+] Python decompile OK: {name} ({lines} lines) -> {out_file}")
            if name == "dis_fallback":
                print("    WARNING: dis output is bytecode, not source. Try installing uncompyle6.")
            return result
        else:
            print(f"  [-] {name}: failed ({stderr[:80].strip()})")

    result["error"] = "All decompilers failed"
    print(f"[!] Python decompile FAILED for {file_path}")
    print("    Install: pip install uncompyle6 (Python 3.8-), or pycdc (all versions)")
    return result


# ── Java ───────────────────────────────────────────────────────────────

def decompile_java(file_path: str, output: str = None) -> dict:
    """Decompile Java .class or .jar file."""
    wsl_file = _wsl_path(file_path)
    out_dir = output or str(Path(file_path).parent / "java_src")
    result = {"file": file_path, "tool": None, "output": out_dir, "success": False}

    ext = Path(file_path).suffix.lower()
    is_jar = ext in (".jar", ".zip", ".apk")

    decompilers = [
        # jadx: best for JAR/APK
        ("jadx", ["jadx", "-d", _wsl_path(out_dir), "--no-imports", wsl_file] if is_jar
                 else ["jadx", "-d", _wsl_path(out_dir), wsl_file]),
        # procyon: good for single .class
        ("procyon", ["procyon", "-o", _wsl_path(out_dir), wsl_file]),
        # CFR: alternative
        ("cfr", ["java", "-jar", "/usr/share/cfr/cfr.jar", wsl_file]),
        # javap: disassembly fallback
        ("javap", ["javap", "-c", "-p", "-verbose", wsl_file]),
    ]

    for name, cmd in decompilers:
        stdout, stderr, rc = _run_wsl(cmd, timeout=120)

        if name in ("jadx", "procyon"):
            # These write to output dir
            if rc == 0:
                result["tool"] = name
                result["success"] = True
                print(f"[+] Java decompile OK: {name} -> {out_dir}")
                return result
        else:
            # CFR and javap write to stdout
            if rc == 0 and stdout.strip():
                result["tool"] = name
                result["success"] = True
                Path(out_dir).mkdir(parents=True, exist_ok=True)
                out_file = Path(out_dir) / "decompiled.java"
                out_file.write_text(stdout, encoding="utf-8")
                print(f"[+] Java decompile OK: {name} -> {out_file}")
                return result

        print(f"  [-] {name}: failed ({stderr[:80].strip()})")

    result["error"] = "All decompilers failed"
    print(f"[!] Java decompile FAILED. Install: apt install jadx / procyon")
    return result


# ── .NET ───────────────────────────────────────────────────────────────

def decompile_dotnet(file_path: str, output: str = None) -> dict:
    """Decompile .NET assembly (.exe/.dll)."""
    wsl_file = _wsl_path(file_path)
    out_dir = output or str(Path(file_path).parent / "dotnet_src")
    result = {"file": file_path, "tool": None, "output": out_dir, "success": False}

    decompilers = [
        # ILSpy CLI (ilspycmd)
        ("ilspycmd", ["ilspycmd", "-p", "-o", _wsl_path(out_dir), wsl_file]),
        # monodis: IL disassembly
        ("monodis", ["monodis", "--output=" + _wsl_path(out_dir) + "/disasm.il", wsl_file]),
    ]

    for name, cmd in decompilers:
        stdout, stderr, rc = _run_wsl(cmd, timeout=120)

        if rc == 0:
            result["tool"] = name
            result["success"] = True
            print(f"[+] .NET decompile OK: {name} -> {out_dir}")
            return result

        print(f"  [-] {name}: failed ({stderr[:80].strip()})")

    # Fallback: strings extraction for quick analysis
    print("  [*] Falling back to strings extraction...")
    stdout, _, _ = _run_wsl(["strings", wsl_file])
    if stdout:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        out_file = Path(out_dir) / "strings.txt"
        out_file.write_text(stdout, encoding="utf-8")
        result["tool"] = "strings"
        result["success"] = True
        result["note"] = "strings only, decompiler not available"
        print(f"  [+] Strings extracted -> {out_file}")

    return result


# ── WebAssembly ────────────────────────────────────────────────────────

def decompile_wasm(file_path: str, output: str = None) -> dict:
    """Decompile WebAssembly .wasm to WAT text format."""
    wsl_file = _wsl_path(file_path)
    out_file = output or str(Path(file_path).with_suffix(".wat"))
    result = {"file": file_path, "tool": None, "output": out_file, "success": False}

    decompilers = [
        # wasm2wat: standard WAT output
        ("wasm2wat", ["wasm2wat", wsl_file, "-o", _wsl_path(out_file)]),
        # wasm-decompile: higher-level C-like output
        ("wasm-decompile", ["wasm-decompile", wsl_file, "-o", _wsl_path(out_file)]),
        # wasm-objdump: disassembly fallback
        ("wasm-objdump", ["wasm-objdump", "-d", wsl_file]),
    ]

    for name, cmd in decompilers:
        stdout, stderr, rc = _run_wsl(cmd, timeout=30)

        if name in ("wasm2wat", "wasm-decompile"):
            if rc == 0 and Path(out_file).exists():
                result["tool"] = name
                result["success"] = True
                print(f"[+] WASM decompile OK: {name} -> {out_file}")
                return result
        else:
            if rc == 0 and stdout.strip():
                Path(out_file).write_text(stdout, encoding="utf-8")
                result["tool"] = name
                result["success"] = True
                print(f"[+] WASM disasm OK: {name} -> {out_file}")
                return result

        print(f"  [-] {name}: failed ({stderr[:80].strip()})")

    result["error"] = "All decompilers failed"
    print(f"[!] WASM decompile FAILED. Install: apt install wabt")
    return result


# ============================================================================
# Auto-dispatch
# ============================================================================

DISPATCH = {
    "python": decompile_python,
    "python_pyc": decompile_python,
    "python_pyc_27": decompile_python,
    "java": decompile_java,
    "java_class": decompile_java,
    "java_jar": decompile_java,
    "android_apk": decompile_java,
    "dotnet": decompile_dotnet,
    "wasm": decompile_wasm,
}


def decompile_auto(file_path: str, output: str = None) -> dict:
    """Auto-detect file type and decompile."""
    info = detect_file_type(file_path)
    ftype = info["type"]

    if ftype in DISPATCH:
        print(f"[+] Detected: {ftype} ({json.dumps(info.get('details', {}))})")
        return DISPATCH[ftype](file_path, output)
    elif ftype == "native_pe":
        print(f"[!] Native PE (not .NET) - use IDA/Ghidra instead")
        return {"file": file_path, "type": ftype, "success": False, "error": "native PE, not bytecode"}
    else:
        print(f"[!] Unknown file type: {ftype}")
        print(f"    Magic bytes: {open(file_path, 'rb').read(8).hex()}")
        return {"file": file_path, "type": ftype, "success": False, "error": "unknown type"}


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="Bytecode decompiler chain")
    sub = p.add_subparsers(dest="cmd", required=True)

    # detect
    s = sub.add_parser("detect", help="Detect bytecode file type")
    s.add_argument("file", help="File to analyze")

    # decompile
    s = sub.add_parser("decompile", help="Decompile bytecode file")
    s.add_argument("file", help="File to decompile")
    s.add_argument("-o", "--output", default=None, help="Output file/directory")
    s.add_argument("--type", default=None, choices=list(DISPATCH.keys()),
                   help="Force file type (skip auto-detect)")

    args = p.parse_args()

    if args.cmd == "detect":
        info = detect_file_type(args.file)
        print(json.dumps(info, indent=2))

    elif args.cmd == "decompile":
        if args.type:
            if args.type in DISPATCH:
                DISPATCH[args.type](args.file, args.output)
            else:
                print(f"[!] Unknown type: {args.type}")
        else:
            decompile_auto(args.file, args.output)


if __name__ == "__main__":
    main()
