#!/usr/bin/env python3
"""
checkpoint.py — Lightweight checkpoint management for agent state tracking.

Usage from agents (via py-repl or Bash):
  python tools/checkpoint.py update <challenge_dir> --agent solver --phase 2 \
    --phase-name z3_formulation --status in_progress \
    --completed recon,structure_analysis --in-progress z3_formulation

  python tools/checkpoint.py complete <challenge_dir> --agent solver

  python tools/checkpoint.py fail <challenge_dir> --agent solver --error "timeout on z3"

  python tools/checkpoint.py show <challenge_dir>
"""
import argparse
import json
from datetime import datetime
from pathlib import Path


def load_checkpoint(challenge_dir: Path) -> dict:
    cp = challenge_dir / "checkpoint.json"
    if cp.exists():
        return json.loads(cp.read_text(encoding="utf-8"))
    return {}


def save_checkpoint(challenge_dir: Path, data: dict):
    cp = challenge_dir / "checkpoint.json"
    data["timestamp"] = datetime.now().isoformat()
    cp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def cmd_update(args):
    d = Path(args.challenge_dir)
    cp = load_checkpoint(d)
    cp["agent"] = args.agent
    cp["status"] = args.status or "in_progress"
    if args.phase is not None:
        cp["phase"] = args.phase
    if args.phase_name:
        cp["phase_name"] = args.phase_name
    if args.completed:
        cp["completed"] = args.completed.split(",")
    if args.in_progress:
        cp["in_progress"] = args.in_progress
    save_checkpoint(d, cp)
    print(f"[checkpoint] Updated: {d.name} ({cp['agent']} phase={cp.get('phase','?')})")


def cmd_complete(args):
    d = Path(args.challenge_dir)
    cp = load_checkpoint(d)
    cp["agent"] = args.agent
    cp["status"] = "completed"
    save_checkpoint(d, cp)
    print(f"[checkpoint] Completed: {d.name}")


def cmd_fail(args):
    d = Path(args.challenge_dir)
    cp = load_checkpoint(d)
    cp["agent"] = args.agent
    cp["status"] = "error"
    cp["error"] = args.error or "unknown"
    save_checkpoint(d, cp)
    print(f"[checkpoint] Failed: {d.name} ({args.error})")


def cmd_init(args):
    """Initialize checkpoint for a new challenge (called at pipeline start)."""
    d = Path(args.challenge_dir)
    d.mkdir(parents=True, exist_ok=True)
    cp = load_checkpoint(d)
    if cp and cp.get("status") in ("in_progress", "completed"):
        print(f"[checkpoint] Already exists: {d.name} (status={cp.get('status')})")
        return
    cp = {
        "agent": args.agent,
        "status": "in_progress",
        "phase": 0,
        "phase_name": "init",
        "completed": [],
        "in_progress": "init",
        "critical_facts": {},
        "expected_artifacts": [],
        "produced_artifacts": [],
    }
    save_checkpoint(d, cp)
    print(f"[checkpoint] Initialized: {d.name} ({args.agent})")


def cmd_show(args):
    d = Path(args.challenge_dir)
    cp = load_checkpoint(d)
    if cp:
        print(json.dumps(cp, indent=2))
    else:
        print("No checkpoint found.")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    p_up = sub.add_parser("update")
    p_up.add_argument("challenge_dir")
    p_up.add_argument("--agent", required=True)
    p_up.add_argument("--phase", type=int)
    p_up.add_argument("--phase-name")
    p_up.add_argument("--status", default="in_progress")
    p_up.add_argument("--completed")
    p_up.add_argument("--in-progress")

    p_done = sub.add_parser("complete")
    p_done.add_argument("challenge_dir")
    p_done.add_argument("--agent", required=True)

    p_fail = sub.add_parser("fail")
    p_fail.add_argument("challenge_dir")
    p_fail.add_argument("--agent", required=True)
    p_fail.add_argument("--error")

    p_init = sub.add_parser("init")
    p_init.add_argument("challenge_dir")
    p_init.add_argument("--agent", required=True)

    p_show = sub.add_parser("show")
    p_show.add_argument("challenge_dir")

    args = parser.parse_args()
    dispatch = {
        "update": cmd_update,
        "complete": cmd_complete,
        "fail": cmd_fail,
        "init": cmd_init,
        "show": cmd_show,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
