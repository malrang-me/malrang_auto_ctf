#!/usr/bin/env python3
"""
validate_reversal_map.py — Validate reversal_map.md has required sections.

Ensures reverser produces a complete analysis before handoff to solver.
Blocks handoff if critical sections are missing or empty.

Usage:
  python tools/validate_reversal_map.py <challenge_dir>
  python tools/validate_reversal_map.py <challenge_dir> --strict  # all sections required
  python tools/validate_reversal_map.py <challenge_dir> --fix     # show what's missing

Exit codes: 0 = valid, 1 = missing required sections, 2 = file not found
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Required sections (must be present and non-empty)
REQUIRED_SECTIONS = {
    "Binary Info": "Binary metadata (arch, protections, type)",
    "Input Vectors": "How the binary receives input (stdin/file/argv/network)",
    "Algorithm": "Core algorithm or validation logic",
    "Key Values": "Constants, keys, expected outputs (tool-verified)",
    "Attack Strategy": "Primary and fallback solving approaches",
}

# Optional but recommended
OPTIONAL_SECTIONS = {
    "Vulnerability": "Identified vulnerability type and location",
    "Anti-Debug": "Detected anti-debug techniques and bypass strategy",
    "VM Structure": "Custom VM opcode map and bytecode info",
    "Protections": "Binary protections (checksec output)",
}

# pwn-only fields that must appear inside Binary Info when libc is provided
PWN_LIBC_FIELDS = ("libc_version", "libc_mismatch", "libc_offsets_file")

# Minimum content thresholds
MIN_SECTION_CHARS = 20  # Section must have at least this many chars
MIN_KEY_VALUES = 1      # At least 1 key value entry


def find_reversal_map(challenge_dir: str) -> Path | None:
    """Find reversal_map.md in challenge directory."""
    cdir = Path(challenge_dir)
    candidates = [
        cdir / "reversal_map.md",
        cdir / "artifacts" / "reversal_map.md",
        cdir / "memory" / "reversal_map.md",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def parse_sections(content: str) -> dict[str, str]:
    """Parse markdown into sections by ## headers."""
    sections = {}
    current_header = None
    current_lines = []

    for line in content.splitlines():
        m = re.match(r'^##\s+(.+)', line)
        if m:
            if current_header:
                sections[current_header] = "\n".join(current_lines).strip()
            current_header = m.group(1).strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_header:
        sections[current_header] = "\n".join(current_lines).strip()

    return sections


def validate(challenge_dir: str, strict: bool = False) -> dict:
    """Validate reversal_map.md structure and content."""
    result = {
        "valid": True,
        "file": None,
        "errors": [],
        "warnings": [],
        "sections_found": [],
        "sections_missing": [],
        "score": 0,
    }

    # Find file
    rmap = find_reversal_map(challenge_dir)
    if rmap is None:
        result["valid"] = False
        result["errors"].append("reversal_map.md not found in challenge directory")
        return result

    result["file"] = str(rmap)
    content = rmap.read_text(encoding="utf-8")

    if len(content.strip()) < 50:
        result["valid"] = False
        result["errors"].append(f"File too short ({len(content)} chars) - likely incomplete")
        return result

    # Parse sections
    sections = parse_sections(content)
    result["sections_found"] = list(sections.keys())

    # Check required sections
    check_sections = {**REQUIRED_SECTIONS}
    if strict:
        check_sections.update(OPTIONAL_SECTIONS)

    total_checks = len(check_sections)
    passed = 0

    for section_name, description in check_sections.items():
        # Fuzzy match: "Binary Info" matches "Binary Info", "Binary Information", etc.
        matched = None
        for found_name in sections:
            if section_name.lower() in found_name.lower() or found_name.lower() in section_name.lower():
                matched = found_name
                break
            # Also match partial keywords
            keywords = section_name.lower().split()
            if all(kw in found_name.lower() for kw in keywords):
                matched = found_name
                break

        if matched is None:
            if section_name in REQUIRED_SECTIONS:
                result["errors"].append(f"MISSING required section: ## {section_name} ({description})")
                result["sections_missing"].append(section_name)
                result["valid"] = False
            else:
                result["warnings"].append(f"Missing optional section: ## {section_name} ({description})")
        else:
            section_content = sections[matched]
            if len(section_content) < MIN_SECTION_CHARS:
                result["warnings"].append(f"Section '{matched}' too short ({len(section_content)} chars)")
            else:
                passed += 1

    # Check for Key Values table format (should have | delimited rows)
    key_values_section = None
    for name, content in sections.items():
        if "key" in name.lower() and "value" in name.lower():
            key_values_section = content
            break

    if key_values_section:
        table_rows = [line for line in key_values_section.splitlines() if "|" in line and "---" not in line]
        if len(table_rows) < MIN_KEY_VALUES + 1:  # +1 for header
            result["warnings"].append(f"Key Values table has {max(0, len(table_rows)-1)} entries (expected >= {MIN_KEY_VALUES})")

    # Check for tool verification markers
    verification_markers = ["readelf", "objdump", "strings", "IDA", "GDB", "checksec", "decompile"]
    has_verification = any(marker.lower() in content.lower() for marker in verification_markers)
    if not has_verification:
        result["warnings"].append("No tool verification markers found - constants may be unverified")

    # pwn libc-pinning check
    cdir = Path(challenge_dir)
    libc_provided = any(cdir.glob("libc*.so*")) or any(cdir.rglob("libc*.so*"))
    if libc_provided:
        offsets_json = cdir / "libc_offsets.json"
        if not offsets_json.exists():
            result["errors"].append(
                "libc.so.6 provided but libc_offsets.json missing — "
                "run: python tools/pwn_setup.py " + str(cdir)
            )
            result["valid"] = False
        # reversal_map.md should mention libc fields
        missing_fields = [f for f in PWN_LIBC_FIELDS if f not in content]
        if missing_fields:
            result["warnings"].append(
                "Binary Info missing pwn libc fields: " + ", ".join(missing_fields)
            )

    result["score"] = round(passed / max(total_checks, 1) * 100)

    return result


def print_fix_template(sections_missing: list[str]):
    """Print template for missing sections."""
    print("\n--- Template for missing sections ---\n")
    templates = {
        "Binary Info": """## Binary Info
- File: <name>
- Arch: <x86-64/ARM/MIPS>
- Type: <ELF/PE/Mach-O>
- Protections: <checksec output>
- Stripped: <yes/no>""",
        "Input Vectors": """## Input Vectors
- Source: <stdin/file/argv/network>
- Format: <string/hex/binary>
- Length: <N bytes>""",
        "Algorithm": """## Algorithm / Structure
<Pseudocode or description of the core validation logic>""",
        "Key Values": """## Key Values (all tool-verified)
| Value | Source | Verification |
|-------|--------|-------------|
| <key/constant> | <binary offset/function> | <readelf/objdump/IDA> |""",
        "Attack Strategy": """## Attack Strategy
- Primary: <approach>
- Fallback: <alternative approach>
- Tools: <Z3/angr/brute/manual>""",
        "Anti-Debug": """## Anti-Debug
- Detected: <ptrace/timing/alarm/none>
- Bypass: <LD_PRELOAD/patch/GDB override>
- Tool: `python tools/gdb_auto.py detect <binary>`""",
        "VM Structure": """## VM Structure
- Type: <stack/accumulator/register>
- Opcodes: <count> (see opcode_map below)
- Bytecode: <location in binary>
- Template: `templates/vm_solver.py`""",
    }

    for section in sections_missing:
        if section in templates:
            print(templates[section])
            print()


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="Validate reversal_map.md schema")
    p.add_argument("challenge_dir", help="Challenge directory path")
    p.add_argument("--strict", action="store_true", help="Require optional sections too")
    p.add_argument("--fix", action="store_true", help="Show template for missing sections")
    p.add_argument("--json", action="store_true", help="JSON output only")
    args = p.parse_args()

    result = validate(args.challenge_dir, strict=args.strict)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = "PASS" if result["valid"] else "FAIL"
        print(f"[validate] {status} (score: {result['score']}%)")

        if result["file"]:
            print(f"  File: {result['file']}")
            print(f"  Sections found: {', '.join(result['sections_found'])}")

        for err in result["errors"]:
            print(f"  ERROR: {err}")
        for warn in result["warnings"]:
            print(f"  WARN:  {warn}")

        if args.fix and result["sections_missing"]:
            print_fix_template(result["sections_missing"])

    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
