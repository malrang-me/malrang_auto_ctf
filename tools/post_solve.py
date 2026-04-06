#!/usr/bin/env python3
"""post_solve.py — Single entry point for post-flag bookkeeping.

Replaces the manual post-flag sequence (FLAGS.txt append + learn.py record +
speedrun rebuild + brief report). The orchestrator should call this exactly
once after a flag is verified.

Usage:
    python tools/post_solve.py <challenge_name> --flag "DH{...}" --category crypto
    python tools/post_solve.py <challenge_name> --flag "DH{...}" --category rev --difficulty hard
    python tools/post_solve.py <challenge_name> --status failed --category pwn --notes "rop chain leaks"
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLAGS_FILE = ROOT / "FLAGS.txt"
CHALLENGES_DIR = ROOT / "challenges"
LEARN_SCRIPT = ROOT / "tools" / "learn.py"
STAGING_DIR = ROOT / "knowledge" / "writeup_staging"


def mark_midsolve_results(challenge_name: str, succeeded: bool) -> int:
    """Tag midsolve_search staging entries used by this challenge.
    Sets `succeeded=True/False` so absorption can prefer winners."""
    if not STAGING_DIR.exists():
        return 0
    tagged = 0
    for f in STAGING_DIR.glob("midsolve_*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if d.get("kind") != "midsolve":
            continue
        if d.get("used_in_challenge") != challenge_name:
            continue
        if d.get("succeeded") is not None:
            continue
        d["succeeded"] = succeeded
        d["resolved_at"] = datetime.now().isoformat()
        f.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        tagged += 1
    return tagged


def append_flag(name: str, flag: str) -> bool:
    """Append `<name> - <flag>` to FLAGS.txt unless that exact pair is already there."""
    line = f"{name} - {flag}"
    if FLAGS_FILE.exists():
        existing = FLAGS_FILE.read_text(encoding="utf-8", errors="replace")
        if line in existing.splitlines():
            return False
    with FLAGS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return True


def run_learn(challenge_dir: Path, status: str, category: str,
              flag: str, notes: str) -> dict:
    """Invoke learn.py record (which now cascades to kb.db + speedrun.db)."""
    cmd = [
        sys.executable, str(LEARN_SCRIPT), "record",
        "--challenge-dir", str(challenge_dir),
        "--status", status,
        "--category", category,
    ]
    if flag:
        cmd += ["--flag", flag]
    if notes:
        cmd += ["--notes", notes]
    r = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        cwd=str(ROOT), timeout=120,
    )
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    # learn.py prints a JSON summary as the last block — try to extract it
    summary = {}
    m = re.search(r"\{[\s\S]*\}\s*$", out)
    if m:
        try:
            summary = json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return {
        "returncode": r.returncode,
        "summary": summary,
        "stdout": out,
        "stderr": err,
    }


def render_report(name: str, category: str, difficulty: str,
                  flag: str, status: str, learn_result: dict) -> str:
    cascade = (learn_result.get("summary") or {}).get("cascade", {})
    kb_ok = cascade.get("kb_indexed", False)
    sr_ok = cascade.get("speedrun_rebuilt", False)
    sr_msg = cascade.get("speedrun_message", "")
    sr_count = ""
    m = re.search(r"Indexed (\d+) entries", sr_msg)
    if m:
        sr_count = f" ({m.group(1)} entries)"

    if status == "success":
        flag_line = f"  플래그:    {flag}"
    else:
        flag_line = f"  상태:      FAILED"

    return (
        "═══════════════════════════════════════\n"
        f"  문제: {name} | 카테고리: {category} | 난이도: {difficulty}\n"
        f"{flag_line}\n"
        f"  학습 cascade: kb.db {'OK' if kb_ok else 'FAIL'}, "
        f"speedrun.db {'OK' if sr_ok else 'FAIL'}{sr_count}\n"
        f"  타임스탬프:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "═══════════════════════════════════════"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("name", help="Challenge folder name (under challenges/)")
    p.add_argument("--flag", default="", help="Recovered flag (required for success)")
    p.add_argument("--category", default="unknown")
    p.add_argument("--difficulty", default="medium",
                   choices=["easy", "medium", "hard", "trivial", "unknown"])
    p.add_argument("--status", default="success", choices=["success", "failed"])
    p.add_argument("--notes", default="")
    p.add_argument("--challenge-dir", help="Override challenge directory path")
    args = p.parse_args()

    challenge_dir = Path(args.challenge_dir) if args.challenge_dir else CHALLENGES_DIR / args.name
    if not challenge_dir.is_dir():
        print(f"[post_solve] ERROR: {challenge_dir} not found", file=sys.stderr)
        return 1

    if args.status == "success" and not args.flag:
        print("[post_solve] ERROR: --flag required for status=success", file=sys.stderr)
        return 1

    # 1. FLAGS.txt
    if args.status == "success":
        appended = append_flag(args.name, args.flag)
        print(f"[post_solve] FLAGS.txt {'appended' if appended else 'already present'}")

    # 1b. Tag midsolve_search staging entries with success/fail
    tagged = mark_midsolve_results(args.name, succeeded=(args.status == "success"))
    if tagged:
        print(f"[post_solve] tagged {tagged} midsolve search results "
              f"(succeeded={args.status == 'success'})")

    # 2. learn.py record (cascades to kb.db + speedrun.db automatically)
    learn_result = run_learn(challenge_dir, args.status, args.category, args.flag, args.notes)
    if learn_result["returncode"] != 0:
        print(f"[post_solve] learn.py FAILED:\n{learn_result['stderr'] or learn_result['stdout']}",
              file=sys.stderr)
        return learn_result["returncode"]

    # 3. Brief report (orch-rendered, not reporter agent)
    print()
    print(render_report(args.name, args.category, args.difficulty,
                        args.flag, args.status, learn_result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
