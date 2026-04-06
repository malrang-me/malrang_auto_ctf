#!/usr/bin/env python3
"""absorb_memories.py — Merge challenges/<name>/memory/*.md into CTF_SPEEDRUN_MEMORY.md.

Scans every `challenges/*/memory/{recon,strategy,discoveries,failures}.md`,
skips empty/stub files, and appends a new SPEEDRUN entry for any challenge
not already covered. After absorption, optionally archives the memory dir
and rebuilds the FTS5 index.

Usage:
    python tools/absorb_memories.py scan                      # report only, no writes
    python tools/absorb_memories.py absorb                    # append entries
    python tools/absorb_memories.py absorb --archive          # also move memory/ -> memory.archived/
    python tools/absorb_memories.py absorb --challenge hehe   # single challenge
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_DIR = ROOT / "challenges"
SPEEDRUN_MD = ROOT / "knowledge" / "CTF_SPEEDRUN_MEMORY.md"
SPEEDRUN_SCRIPT = ROOT / "tools" / "speedrun_db.py"

MEMORY_FILES = ("recon.md", "strategy.md", "discoveries.md", "failures.md")
STUB_THRESHOLD = 80  # bytes — anything ≤ this is treated as a stub heading


def read_clean(path: Path) -> str:
    """Read file, strip leading heading line if present, return body."""
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    # Remove just the first '# Heading' line if it's a bare title
    lines = text.splitlines()
    if lines and lines[0].lstrip().startswith("#"):
        lines = lines[1:]
    return "\n".join(lines).strip()


def is_stub(path: Path) -> bool:
    if not path.exists():
        return True
    if path.stat().st_size <= STUB_THRESHOLD:
        return True
    return not read_clean(path)


def collect_memory(challenge_dir: Path) -> dict[str, str]:
    """Return dict of {file_stem: body} for non-stub memory files."""
    out: dict[str, str] = {}
    mem_dir = challenge_dir / "memory"
    if not mem_dir.is_dir():
        return out
    for fname in MEMORY_FILES:
        p = mem_dir / fname
        if not is_stub(p):
            out[p.stem] = read_clean(p)
    return out


def existing_entry_names(speedrun_md: Path) -> set[str]:
    """Lowercased set of challenge names already in SPEEDRUN_MEMORY.md."""
    if not speedrun_md.exists():
        return set()
    text = speedrun_md.read_text(encoding="utf-8", errors="replace")
    names: set[str] = set()
    for m in re.finditer(r"^##\s+Entry\s+\d+\s*-\s*(.+?)\s*$", text, re.MULTILINE):
        name = m.group(1).strip()
        # Strip trailing parentheticals like "(crypto version)"
        bare = re.sub(r"\s*\([^)]*\)\s*$", "", name).strip()
        names.add(name.lower())
        names.add(bare.lower())
    return names


def next_entry_number(speedrun_md: Path) -> int:
    if not speedrun_md.exists():
        return 1
    text = speedrun_md.read_text(encoding="utf-8", errors="replace")
    nums = [int(m.group(1)) for m in re.finditer(r"^##\s+Entry\s+(\d+)", text, re.MULTILINE)]
    return (max(nums) + 1) if nums else 1


def detect_category(challenge_dir: Path) -> str:
    """Best-effort category from meta.yaml or category file."""
    meta = challenge_dir / "meta.yaml"
    if meta.exists():
        try:
            text = meta.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^category:\s*(\S+)", text, re.MULTILINE)
            if m:
                return m.group(1).strip().strip("\"'")
        except OSError:
            pass
    return "unknown"


def build_entry(entry_num: int, name: str, category: str, mem: dict[str, str]) -> str:
    """Render a SPEEDRUN entry block from collected memory sections."""
    today = date.today().isoformat()
    parts = [
        f"## Entry {entry_num:03d} - {name}",
        f"- Challenge: {name}",
        f"- Category: {category}",
        f"- Date: {today}",
        f"- Source: absorbed from challenges/{name}/memory/",
    ]
    section_map = [
        ("recon",       "Fast Detection Signals"),
        ("strategy",    "Winning Chain"),
        ("discoveries", "Key Discoveries"),
        ("failures",    "Failure Signatures -> Immediate Fix"),
    ]
    for key, label in section_map:
        body = mem.get(key, "").strip()
        if not body:
            continue
        # Indent body so it stays under the bullet
        indented = "\n".join("  " + line if line else "" for line in body.splitlines())
        parts.append(f"- {label}:\n{indented}")
    return "\n".join(parts) + "\n"


def cmd_scan(args: argparse.Namespace) -> int:
    existing = existing_entry_names(SPEEDRUN_MD)
    new_count = 0
    skip_existing = 0
    skip_empty = 0
    rows = []
    for cdir in sorted(CHALLENGES_DIR.iterdir()):
        if not cdir.is_dir():
            continue
        if args.challenge and cdir.name != args.challenge:
            continue
        mem = collect_memory(cdir)
        if not mem:
            skip_empty += 1
            continue
        if cdir.name.lower() in existing:
            skip_existing += 1
            rows.append(("SKIP-EXISTS", cdir.name, sum(len(v) for v in mem.values()), list(mem)))
            continue
        new_count += 1
        rows.append(("NEW", cdir.name, sum(len(v) for v in mem.values()), list(mem)))

    for status, name, size, sections in rows:
        print(f"  {status:12s} {name:35s} {size:6d}B  {sections}")
    print()
    print(f"[scan] new: {new_count} | already-in-SPEEDRUN: {skip_existing} | empty/stub: {skip_empty}")
    return 0


def cmd_absorb(args: argparse.Namespace) -> int:
    if not SPEEDRUN_MD.exists():
        print(f"[absorb] ERROR: {SPEEDRUN_MD} not found", file=sys.stderr)
        return 1

    existing = existing_entry_names(SPEEDRUN_MD)
    next_num = next_entry_number(SPEEDRUN_MD)
    appended: list[str] = []
    archived: list[str] = []

    for cdir in sorted(CHALLENGES_DIR.iterdir()):
        if not cdir.is_dir():
            continue
        if args.challenge and cdir.name != args.challenge:
            continue
        mem = collect_memory(cdir)
        if not mem:
            continue
        if cdir.name.lower() in existing:
            continue

        category = detect_category(cdir)
        entry = build_entry(next_num, cdir.name, category, mem)

        with SPEEDRUN_MD.open("a", encoding="utf-8") as fh:
            fh.write("\n" + entry)
        appended.append(f"Entry {next_num:03d} - {cdir.name}")
        existing.add(cdir.name.lower())
        next_num += 1

        if args.archive:
            mem_dir = cdir / "memory"
            archive_dir = cdir / "memory.archived"
            if archive_dir.exists():
                shutil.rmtree(archive_dir)
            mem_dir.rename(archive_dir)
            archived.append(cdir.name)

    print(f"[absorb] appended {len(appended)} entries:")
    for line in appended:
        print(f"  + {line}")
    if archived:
        print(f"[absorb] archived {len(archived)} memory dirs")

    if appended and not args.no_rebuild:
        try:
            r = subprocess.run(
                [sys.executable, str(SPEEDRUN_SCRIPT), "rebuild"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                cwd=str(ROOT), timeout=60,
            )
            print(f"[absorb] speedrun.db {'OK' if r.returncode == 0 else 'FAIL'}: "
                  f"{(r.stdout or r.stderr).strip()[:200]}")
        except Exception as e:
            print(f"[absorb] speedrun.db rebuild error: {e}")

    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Report what would be absorbed (no writes)")
    s.add_argument("--challenge", help="Limit to one challenge name")

    s = sub.add_parser("absorb", help="Append new entries to SPEEDRUN_MEMORY.md")
    s.add_argument("--challenge", help="Limit to one challenge name")
    s.add_argument("--archive", action="store_true",
                   help="Move memory/ -> memory.archived/ after absorption")
    s.add_argument("--no-rebuild", action="store_true",
                   help="Skip speedrun.db rebuild")

    args = p.parse_args()
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "absorb":
        return cmd_absorb(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
