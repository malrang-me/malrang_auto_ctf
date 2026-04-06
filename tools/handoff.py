#!/usr/bin/env python3
"""
handoff.py — Structured handoff protocol helper for agent-to-agent transitions.

Generates and validates handoff blocks that agents use to pass context.

Usage:
  python tools/handoff.py create --from reverser --to solver \
    --artifact reversal_map.md --confidence PASS \
    --result "RSA with leaked phi, n=1024 bits" \
    --next "Build z3 model for phi factoring" \
    --challenge-dir challenges/MyChallenge

  python tools/handoff.py validate <challenge_dir>

  python tools/handoff.py history <challenge_dir>
"""
import argparse
import json
from datetime import datetime
from pathlib import Path


def create_handoff(
    from_agent: str,
    to_agent: str,
    artifact: str,
    confidence: str,
    result: str,
    next_action: str,
    blockers: str = "None",
    knowledge_context: str = "",
    challenge_dir: str = ".",
) -> str:
    """Create a structured handoff block and save to challenge dir."""
    block = {
        "from": from_agent,
        "to": to_agent,
        "artifact": artifact,
        "confidence": confidence,
        "result": result,
        "next_action": next_action,
        "blockers": blockers,
        "knowledge_context": knowledge_context,
        "timestamp": datetime.now().isoformat(),
    }

    # Save to handoff log
    cdir = Path(challenge_dir)
    cdir.mkdir(parents=True, exist_ok=True)
    log_file = cdir / "handoff_log.json"

    history = []
    if log_file.exists():
        try:
            history = json.loads(log_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    history.append(block)
    log_file.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")

    # Generate text block for agent prompt injection
    text = f"""[HANDOFF from @{from_agent} to @{to_agent}]
- Finding/Artifact: {artifact}
- Confidence: {confidence}
- Key Result: {result}
- Next Action: {next_action}
- Blockers: {blockers}"""
    if knowledge_context:
        text += f"\n[KNOWLEDGE CONTEXT]: {knowledge_context}"

    return text


def cmd_create(args):
    text = create_handoff(
        from_agent=args.from_agent,
        to_agent=args.to_agent,
        artifact=args.artifact,
        confidence=args.confidence,
        result=args.result,
        next_action=args.next_action,
        blockers=args.blockers or "None",
        knowledge_context=args.knowledge or "",
        challenge_dir=args.challenge_dir,
    )
    print(text)


def cmd_validate(args):
    """Validate that a challenge dir has proper handoff history."""
    cdir = Path(args.challenge_dir)
    log_file = cdir / "handoff_log.json"

    if not log_file.exists():
        print("[WARN] No handoff_log.json found — agents may not be using handoff protocol")
        return

    history = json.loads(log_file.read_text(encoding="utf-8"))
    issues = []

    for i, h in enumerate(history):
        # Check required fields
        for field in ["from", "to", "artifact", "confidence", "result", "next_action"]:
            if not h.get(field):
                issues.append(f"Entry {i}: missing '{field}'")

        # Check confidence values
        if h.get("confidence") not in ("PASS", "PARTIAL", "FAIL"):
            issues.append(f"Entry {i}: invalid confidence '{h.get('confidence')}' (must be PASS/PARTIAL/FAIL)")

        # Check artifact exists
        artifact = cdir / h.get("artifact", "")
        mem_artifact = cdir / "memory" / h.get("artifact", "")
        if not artifact.exists() and not mem_artifact.exists():
            issues.append(f"Entry {i}: artifact '{h.get('artifact')}' not found")

    if issues:
        print(f"[FAIL] {len(issues)} issue(s):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print(f"[PASS] {len(history)} handoff(s) validated")


def cmd_history(args):
    """Show handoff history for a challenge."""
    cdir = Path(args.challenge_dir)
    log_file = cdir / "handoff_log.json"

    if not log_file.exists():
        print("No handoff history.")
        return

    history = json.loads(log_file.read_text(encoding="utf-8"))
    for i, h in enumerate(history):
        print(f"[{i+1}] @{h['from']} -> @{h['to']} ({h['confidence']}) at {h.get('timestamp','?')}")
        print(f"     Result: {h['result']}")
        print(f"     Next:   {h['next_action']}")
        if h.get("blockers", "None") != "None":
            print(f"     Blockers: {h['blockers']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Agent handoff protocol helper")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("create", help="Create a handoff block")
    p.add_argument("--from", dest="from_agent", required=True)
    p.add_argument("--to", dest="to_agent", required=True)
    p.add_argument("--artifact", required=True)
    p.add_argument("--confidence", required=True, choices=["PASS", "PARTIAL", "FAIL"])
    p.add_argument("--result", required=True)
    p.add_argument("--next-action", dest="next_action", required=True)
    p.add_argument("--blockers", default="None")
    p.add_argument("--knowledge", default="")
    p.add_argument("--challenge-dir", default=".")

    p = sub.add_parser("validate", help="Validate handoff history")
    p.add_argument("challenge_dir")

    p = sub.add_parser("history", help="Show handoff history")
    p.add_argument("challenge_dir")

    args = parser.parse_args()
    dispatch = {"create": cmd_create, "validate": cmd_validate, "history": cmd_history}
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
