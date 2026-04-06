#!/usr/bin/env python3
"""
dashboard.py — Metrics dashboard for CTF solve pipeline.

Reads metrics/ctf_runs.jsonl and challenge data to produce a summary report.

Usage:
  python tools/dashboard.py                    # Full dashboard
  python tools/dashboard.py --category crypto  # Filter by category
  python tools/dashboard.py --json             # JSON output for tooling
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
METRICS_FILE = PROJ_ROOT / "metrics" / "ctf_runs.jsonl"
CHALLENGES_DIR = PROJ_ROOT / "challenges"


def load_metrics() -> list[dict]:
    """Load all metrics events."""
    if not METRICS_FILE.exists():
        return []
    events = []
    for line in METRICS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def scan_challenges() -> list[dict]:
    """Scan challenge directories for status."""
    challenges = []
    for d in sorted(CHALLENGES_DIR.iterdir()):
        if not d.is_dir():
            continue
        meta_file = d / "meta.yaml"
        info = {"name": d.name, "category": "unknown", "status": "unknown", "has_solver": False}

        if meta_file.exists():
            content = meta_file.read_text(encoding="utf-8")
            m = re.search(r'category:\s*(\S+)', content)
            if m:
                info["category"] = m.group(1)
            m = re.search(r'status:\s*(\S+)', content)
            if m:
                info["status"] = m.group(1)

        # Check for solver
        for f in ["solve.py", "exploit.py", "solve.sage"]:
            if (d / f).exists() and (d / f).stat().st_size > 200:
                info["has_solver"] = True
                info["solver_file"] = f
                info["solver_size"] = (d / f).stat().st_size
                break

        # Check checkpoint
        cp_file = d / "checkpoint.json"
        if cp_file.exists():
            try:
                cp = json.loads(cp_file.read_text(encoding="utf-8"))
                info["checkpoint_status"] = cp.get("status", "unknown")
                info["checkpoint_agent"] = cp.get("agent", "unknown")
            except (json.JSONDecodeError, OSError):
                pass

        # Check for flag in discoveries
        disc = d / "memory" / "discoveries.md"
        if disc.exists():
            disc_text = disc.read_text(encoding="utf-8", errors="replace")
            if re.search(r'(DH|FLAG|flag|CTF)\{[^}]{3,}\}', disc_text):
                info["has_flag"] = True

        challenges.append(info)
    return challenges


def print_dashboard(challenges: list[dict], events: list[dict], category_filter: str = ""):
    """Print a human-readable dashboard."""
    if category_filter:
        challenges = [c for c in challenges if c["category"] == category_filter]

    total = len(challenges)
    by_status = Counter(c["status"] for c in challenges)
    by_category = Counter(c["category"] for c in challenges)
    with_solver = sum(1 for c in challenges if c["has_solver"])
    with_flag = sum(1 for c in challenges if c.get("has_flag"))
    with_checkpoint = sum(1 for c in challenges if c.get("checkpoint_status"))

    print("=" * 60)
    print("  CTF SOLVE PIPELINE DASHBOARD")
    print("=" * 60)
    print()

    # Overall stats
    success_rate = (by_status.get("solved", 0) / total * 100) if total else 0
    print(f"  Total challenges: {total}")
    print(f"  Success rate:     {by_status.get('solved', 0)}/{total} ({success_rate:.1f}%)")
    print(f"  With solver:      {with_solver}/{total}")
    print(f"  With flag found:  {with_flag}/{total}")
    print(f"  With checkpoint:  {with_checkpoint}/{total}")
    print()

    # By status
    print("  Status breakdown:")
    for status, count in sorted(by_status.items(), key=lambda x: -x[1]):
        bar = "#" * count
        print(f"    {status:12s} {count:3d} {bar}")
    print()

    # By category
    print("  Category breakdown:")
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        solved = sum(1 for c in challenges if c["category"] == cat and c["status"] == "solved")
        print(f"    {cat:12s} {solved}/{count} solved")
    print()

    # Challenge detail table
    print("  Challenge Details:")
    print(f"  {'Name':<25s} {'Category':<10s} {'Status':<10s} {'Solver':<12s} {'Checkpoint':<12s}")
    print("  " + "-" * 69)
    for c in challenges:
        solver_info = c.get("solver_file", "-")
        cp_info = c.get("checkpoint_status", "-")
        flag_marker = " *" if c.get("has_flag") else ""
        print(f"  {c['name']:<25s} {c['category']:<10s} {c['status']:<10s} {solver_info:<12s} {cp_info:<12s}{flag_marker}")
    print()
    if with_flag:
        print("  * = flag found in discoveries")
    print()

    # Event timeline (last 20)
    if events:
        print("  Recent Events (last 20):")
        for e in events[-20:]:
            ts = e.get("timestamp", "?")[:19]
            print(f"    [{ts}] {e.get('event','?'):8s} {e.get('challenge','?')} ({e.get('category','?')})")
    print()
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="CTF Pipeline Dashboard")
    parser.add_argument("--category", default="", help="Filter by category")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    challenges = scan_challenges()
    events = load_metrics()

    if args.json:
        print(json.dumps({
            "challenges": challenges,
            "events": events[-50:],
            "summary": {
                "total": len(challenges),
                "solved": sum(1 for c in challenges if c["status"] == "solved"),
                "with_solver": sum(1 for c in challenges if c["has_solver"]),
                "by_category": dict(Counter(c["category"] for c in challenges)),
            }
        }, indent=2, ensure_ascii=False))
    else:
        print_dashboard(challenges, events, args.category)


if __name__ == "__main__":
    main()
