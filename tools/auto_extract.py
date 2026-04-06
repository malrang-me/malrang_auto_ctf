#!/usr/bin/env python3
"""
auto_extract.py — Auto-extract facts from tool outputs into state.db.

Parses structured outputs from common tools and stores verified facts.
Eliminates manual state.py set calls from agents.

Usage:
  python tools/auto_extract.py checksec <challenge_dir> <binary>
  python tools/auto_extract.py strings <challenge_dir> <binary>
  python tools/auto_extract.py gdb-auto <challenge_dir> <binary>
  python tools/auto_extract.py reversal-map <challenge_dir>
  python tools/auto_extract.py all <challenge_dir> <binary>

Each subcommand runs the tool, parses output, and stores facts in state.db.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run command, try native then WSL fallback."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        r = subprocess.run(["wsl"] + cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _wsl_path(path: str) -> str:
    p = Path(path).resolve()
    s = str(p).replace("\\", "/")
    m = re.match(r"([A-Za-z]):/(.+)", s)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return s


def _set_fact(challenge_dir: str, key: str, value: str, source: str, agent: str = "auto_extract"):
    """Store a fact in state.db via state.py."""
    env = os.environ.copy()
    env["CHALLENGE_DIR"] = str(Path(challenge_dir).resolve())

    cmd = [
        "python", "tools/state.py", "set",
        "--key", key,
        "--val", value,
        "--agent", agent,
    ]
    if source:
        cmd.extend(["--src", source])

    subprocess.run(cmd, env=env, capture_output=True, timeout=10)


# ============================================================================
# Extractors
# ============================================================================

def extract_checksec(challenge_dir: str, binary: str) -> dict:
    """Run checksec and extract protections as facts."""
    wsl_bin = _wsl_path(binary)
    output = _run(["checksec", "--file=" + wsl_bin])
    if not output:
        output = _run(["pwn", "checksec", wsl_bin])

    facts = {}
    if not output:
        return facts

    # Save raw output for source verification
    out_file = Path(challenge_dir) / "checksec_output.txt"
    out_file.write_text(output, encoding="utf-8")
    src = str(out_file)

    # Parse checksec output
    patterns = {
        "arch": r"Arch:\s*(.+)",
        "relro": r"RELRO:\s*(.+)",
        "stack_canary": r"Stack:\s*(.+)",
        "nx": r"NX:\s*(.+)",
        "pie": r"PIE:\s*(.+)",
        "rpath": r"RPATH:\s*(.+)",
        "runpath": r"RUNPATH:\s*(.+)",
        "fortify": r"FORTIFY:\s*(.+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, output, re.I)
        if m:
            val = m.group(1).strip()
            facts[key] = val
            _set_fact(challenge_dir, key, val, src)

    print(f"[auto_extract] checksec: {len(facts)} facts extracted")
    return facts


def extract_strings(challenge_dir: str, binary: str) -> dict:
    """Run filtered strings and extract interesting patterns as facts."""
    wsl_bin = _wsl_path(binary)
    output = _run(["strings", wsl_bin])
    if not output:
        return {}

    facts = {}

    # Flag format detection
    flag_patterns = [
        (r"(DH\{[^}]*\})", "flag_format_DH"),
        (r"(flag\{[^}]*\})", "flag_format_flag"),
        (r"(CTF\{[^}]*\})", "flag_format_CTF"),
    ]
    for pattern, key in flag_patterns:
        m = re.search(pattern, output)
        if m:
            facts[key] = m.group(1)

    # Success/failure messages
    for pattern, key in [
        (r"(correct|success|congratul|right|good job)", "success_string"),
        (r"(wrong|incorrect|fail|denied|invalid|nope)", "failure_string"),
    ]:
        matches = re.findall(pattern, output, re.I)
        if matches:
            facts[key] = matches[0]

    # Crypto-related strings
    for pattern, key in [
        (r"AES|aes", "crypto_aes"),
        (r"RSA|rsa", "crypto_rsa"),
        (r"SHA|sha256|sha1|md5", "crypto_hash"),
        (r"base64|Base64", "encoding_base64"),
    ]:
        if re.search(pattern, output):
            facts[key] = "detected"

    # Anti-debug strings
    for pattern, key in [
        (r"/proc/self/status", "anti_debug_tracerpid"),
        (r"ptrace", "anti_debug_ptrace_str"),
        (r"IsDebuggerPresent", "anti_debug_windows"),
    ]:
        if re.search(pattern, output, re.I):
            facts[key] = "detected"

    # Save filtered output
    if facts:
        out_file = Path(challenge_dir) / "strings_filtered.txt"
        filtered = "\n".join(f"{k}: {v}" for k, v in facts.items())
        out_file.write_text(filtered, encoding="utf-8")
        src = str(out_file)
        for key, val in facts.items():
            _set_fact(challenge_dir, key, str(val), src)

    print(f"[auto_extract] strings: {len(facts)} facts extracted")
    return facts


def extract_gdb_auto(challenge_dir: str, binary: str) -> dict:
    """Run gdb_auto.py detect and store anti-debug facts."""
    try:
        r = subprocess.run(
            ["python", "tools/gdb_auto.py", "detect", binary],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return {}
        data = json.loads(r.stdout)
    except Exception:
        return {}

    facts = {}

    # Save raw output
    out_file = Path(challenge_dir) / "gdb_auto_detect.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    src = str(out_file)

    if data.get("has_anti_debug"):
        facts["has_anti_debug"] = "true"
        facts["anti_debug_techniques"] = ",".join(data.get("summary", []))
        facts["anti_debug_bypass"] = "; ".join(data.get("recommended_bypass", []))

        for key, val in facts.items():
            _set_fact(challenge_dir, key, val, src)

    print(f"[auto_extract] gdb_auto: {len(facts)} facts extracted")
    return facts


def extract_reversal_map(challenge_dir: str) -> dict:
    """Parse reversal_map.md and extract key facts."""
    cdir = Path(challenge_dir)
    rmap = cdir / "reversal_map.md"
    if not rmap.exists():
        rmap = cdir / "artifacts" / "reversal_map.md"
    if not rmap.exists():
        return {}

    content = rmap.read_text(encoding="utf-8")
    facts = {}
    src = str(rmap)

    # Extract from Key Values table
    in_table = False
    for line in content.splitlines():
        if re.match(r'##.*Key\s*Value', line, re.I):
            in_table = True
            continue
        if in_table:
            if line.startswith("##"):
                break
            m = re.match(r'\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|', line)
            if m and "---" not in line and "Value" not in m.group(1):
                key_name = m.group(1).strip().lower().replace(" ", "_")
                val = m.group(2).strip()
                if key_name and val:
                    facts[f"kv_{key_name}"] = val

    # Extract vulnerability type
    vuln_match = re.search(r'##.*Vulnerability.*\n-\s*Type[:\s]*(.+)', content, re.I)
    if vuln_match:
        facts["vuln_type"] = vuln_match.group(1).strip()

    # Extract attack strategy
    strategy_match = re.search(r'##.*Attack\s*Strategy.*\n-\s*Primary[:\s]*(.+)', content, re.I)
    if strategy_match:
        facts["attack_primary"] = strategy_match.group(1).strip()

    for key, val in facts.items():
        _set_fact(challenge_dir, key, val, src)

    print(f"[auto_extract] reversal_map: {len(facts)} facts extracted")
    return facts


def extract_all(challenge_dir: str, binary: str) -> dict:
    """Run all extractors and return combined facts."""
    all_facts = {}
    all_facts.update(extract_checksec(challenge_dir, binary))
    all_facts.update(extract_strings(challenge_dir, binary))
    all_facts.update(extract_gdb_auto(challenge_dir, binary))
    all_facts.update(extract_reversal_map(challenge_dir))
    print(f"\n[auto_extract] Total: {len(all_facts)} facts extracted to state.db")
    return all_facts


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="Auto-extract facts from tool outputs")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("checksec", "strings", "gdb-auto"):
        s = sub.add_parser(name, help=f"Extract facts from {name}")
        s.add_argument("challenge_dir")
        s.add_argument("binary")

    s = sub.add_parser("reversal-map", help="Extract facts from reversal_map.md")
    s.add_argument("challenge_dir")

    s = sub.add_parser("all", help="Run all extractors")
    s.add_argument("challenge_dir")
    s.add_argument("binary")

    args = p.parse_args()

    dispatch = {
        "checksec": lambda: extract_checksec(args.challenge_dir, args.binary),
        "strings": lambda: extract_strings(args.challenge_dir, args.binary),
        "gdb-auto": lambda: extract_gdb_auto(args.challenge_dir, args.binary),
        "reversal-map": lambda: extract_reversal_map(args.challenge_dir),
        "all": lambda: extract_all(args.challenge_dir, args.binary),
    }

    result = dispatch[args.cmd]()
    if result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
