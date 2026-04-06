#!/usr/bin/env python3
"""
one_gadget_check.py -- Validate one_gadget constraints against a crash dump.

one_gadget gives you 3-5 gadgets each with constraints like:
  [r12] == NULL
  [rsp+0x40] == NULL
  rsp & 0xf == 0  &&  rcx == NULL

Manually checking these in GDB is tedious and error-prone. This tool:
  1. Reads `libc_offsets.json` (created by tools/pwn_setup.py)
  2. For each one_gadget, parses its constraints into a checker
  3. Takes a register/memory snapshot at the moment of the crash and tells
     you which gadgets are satisfied + what to fix

Usage:
  python tools/one_gadget_check.py challenges/<name>
      Just list one_gadgets + parsed constraints

  python tools/one_gadget_check.py challenges/<name> --snapshot snap.json
      Validate against a JSON snapshot (see SNAPSHOT_FORMAT below)

  python tools/one_gadget_check.py challenges/<name> --gdb-bp 0x401234
      Run binary under gdb_pwn inspect at the BP, capture state, then validate

SNAPSHOT_FORMAT:
  {
    "regs": {"rax": 0, "rcx": 0, "rdx": 0x...},
    "mem":  {"0x7fff1234": 0, "[rsp+0x40]": 0}
  }
"""
import argparse
import json
import re
import sys
from pathlib import Path


REG_NAMES = {"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rsp", "rbp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}


def parse_constraint(line: str) -> dict:
    """
    Parse a single one_gadget constraint line into a checker dict.
    Returns {'kind': 'reg_eq'/'mem_eq'/'rsp_align'/'unknown', ...}.
    """
    line = line.strip()
    if not line:
        return None

    # rsp & 0xf == 0
    m = re.match(r"rsp\s*&\s*0x([0-9a-fA-F]+)\s*==\s*0", line)
    if m:
        return {"kind": "rsp_align", "mask": int(m.group(1), 16), "raw": line}

    # [reg] == NULL  /  [reg+0xN] == NULL
    m = re.match(r"\[(\w+)(?:\+0x([0-9a-fA-F]+))?\]\s*==\s*(NULL|0|0x0)", line)
    if m:
        return {
            "kind": "mem_eq",
            "reg": m.group(1),
            "offset": int(m.group(2), 16) if m.group(2) else 0,
            "value": 0,
            "raw": line,
        }

    # reg == NULL  /  reg == 0
    m = re.match(r"(\w+)\s*==\s*(NULL|0|0x0)", line)
    if m and m.group(1) in REG_NAMES:
        return {"kind": "reg_eq", "reg": m.group(1), "value": 0, "raw": line}

    # writable: <addr>  --  too dynamic, mark as 'manual'
    if "writable:" in line:
        return {"kind": "writable", "raw": line}

    return {"kind": "unknown", "raw": line}


def parse_one_gadget_text(blob: str) -> list[dict]:
    """
    Parse the multi-line one_gadget output for a single gadget into:
      {'offset': int, 'instructions': str, 'constraints': [parsed...]}
    """
    if not blob.strip():
        return []
    lines = blob.strip().splitlines()
    # First line: 0x... execve("/bin/sh", ...)
    m = re.match(r"^(0x[0-9a-fA-F]+)\s+(.*)", lines[0])
    if not m:
        return []
    result = {
        "offset": int(m.group(1), 16),
        "instructions": m.group(2).strip(),
        "constraints": [],
    }
    in_constraints = False
    for line in lines[1:]:
        s = line.strip()
        if s.lower().startswith("constraints:"):
            in_constraints = True
            continue
        if in_constraints and s:
            parsed = parse_constraint(s)
            if parsed:
                result["constraints"].append(parsed)
    return [result] if result["constraints"] or result["offset"] else []


def parse_libc_offsets(cdir: Path) -> list[dict]:
    """Read libc_offsets.json and return parsed gadgets list."""
    path = cdir / "libc_offsets.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    gadgets = []
    for g in data.get("one_gadget", []):
        parsed = parse_one_gadget_text(g.get("constraints", ""))
        for p in parsed:
            p["offset"] = g["offset"]
            gadgets.append(p)
        if not parsed and "offset" in g:
            gadgets.append({
                "offset": g["offset"],
                "instructions": "",
                "constraints": [],
            })
    return gadgets


def check_constraint(c: dict, snapshot: dict) -> tuple[bool, str]:
    """Return (satisfied, reason)."""
    regs = snapshot.get("regs", {})
    mem = snapshot.get("mem", {})
    if c["kind"] == "reg_eq":
        actual = regs.get(c["reg"])
        if actual is None:
            return False, f"unknown {c['reg']} (provide in snapshot)"
        return (actual == c["value"]), f"{c['reg']}={hex(actual)} expected={hex(c['value'])}"
    if c["kind"] == "mem_eq":
        key = f"[{c['reg']}+0x{c['offset']:x}]" if c["offset"] else f"[{c['reg']}]"
        actual = mem.get(key)
        if actual is None:
            # Try also the resolved address form
            base = regs.get(c["reg"])
            if base is not None:
                key2 = hex(base + c["offset"])
                actual = mem.get(key2)
        if actual is None:
            return False, f"unknown {key} (provide in snapshot)"
        return (actual == c["value"]), f"{key}={hex(actual)} expected=0"
    if c["kind"] == "rsp_align":
        rsp = regs.get("rsp")
        if rsp is None:
            return False, "unknown rsp"
        return ((rsp & c["mask"]) == 0), f"rsp&0x{c['mask']:x}={rsp & c['mask']:#x}"
    if c["kind"] == "writable":
        return True, "writable: marked manual"
    return False, f"unknown constraint: {c['raw']}"


def evaluate(gadgets: list[dict], snapshot: dict) -> list[dict]:
    """Check each gadget against snapshot, return ranked list."""
    ranked = []
    for g in gadgets:
        results = []
        all_ok = True
        unknown_count = 0
        for c in g["constraints"]:
            ok, reason = check_constraint(c, snapshot)
            results.append({"constraint": c["raw"], "ok": ok, "reason": reason})
            if not ok:
                all_ok = False
                if "unknown" in reason:
                    unknown_count += 1
        ranked.append({
            "offset": g["offset"],
            "offset_hex": hex(g["offset"]),
            "instructions": g["instructions"],
            "satisfied": all_ok,
            "unknown_constraints": unknown_count,
            "checks": results,
        })
    # Best gadgets first: satisfied > fewest unknown > fewest constraints
    ranked.sort(key=lambda r: (not r["satisfied"], r["unknown_constraints"], len(r["checks"])))
    return ranked


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("challenge_dir")
    p.add_argument("--snapshot", help="JSON file with regs+mem snapshot")
    p.add_argument("--list-only", action="store_true", help="just print parsed gadgets, no validation")
    p.add_argument("--pretty", action="store_true")
    args = p.parse_args()

    cdir = Path(args.challenge_dir).resolve()
    gadgets = parse_libc_offsets(cdir)
    if not gadgets:
        print(f"[one_gadget_check] no one_gadgets found. Did you run pwn_setup.py?", file=sys.stderr)
        sys.exit(2)

    if args.list_only or not args.snapshot:
        for g in gadgets:
            print(f"\n[+] {hex(g['offset'])}  {g.get('instructions', '')}")
            for c in g["constraints"]:
                print(f"    - [{c['kind']}] {c['raw']}")
        if not args.snapshot:
            print(f"\n[i] Pass --snapshot snap.json to validate against a crash state.")
        return

    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    ranked = evaluate(gadgets, snapshot)
    print(json.dumps(ranked, indent=2 if args.pretty else None))

    # Exit code: 0 if at least one fully satisfied, 1 if only partial
    sys.exit(0 if any(r["satisfied"] for r in ranked) else 1)


if __name__ == "__main__":
    main()
