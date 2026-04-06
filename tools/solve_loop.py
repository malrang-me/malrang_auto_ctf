#!/usr/bin/env python3
"""
solve_loop.py — Automated solve-retry loop with decision_tree integration.

Runs solve.py, checks result, and on failure:
  1. Classifies the error (parse/math/timeout/wrong_output)
  2. Records failure in decision_tree
  3. Gets next action suggestion
  4. Outputs structured JSON for the agent to act on

Usage (called by solver/chain agents):
  python tools/solve_loop.py run <challenge_dir> [--max-retries 3] [--timeout 120]
  python tools/solve_loop.py classify <challenge_dir> --output "output text"
  python tools/solve_loop.py suggest <challenge_dir> --agent rev --error-type z3_unsat

The agent reads the JSON output and decides next steps.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

FLAG_RE = re.compile(r"(DH\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|FLAG\{[^}]+\}|picoCTF\{[^}]+\}|INCOGNITO\{[^}]+\})")


# ============================================================================
# Error Classification
# ============================================================================

ERROR_PATTERNS = {
    "parse_error": [
        r"SyntaxError",
        r"IndentationError",
        r"NameError.*not defined",
        r"ImportError",
        r"ModuleNotFoundError",
    ],
    "type_error": [
        r"TypeError",
        r"ValueError",
        r"AttributeError",
        r"KeyError",
        r"IndexError",
    ],
    "z3_unsat": [
        r"UNSAT",
        r"unsat",
        r"no solution",
        r"No solution found",
        r"unsatisfiable",
    ],
    "timeout": [
        r"TimeoutExpired",
        r"Timeout",
        r"TIMEOUT",
        r"timed out",
        r"Connection timed out",
    ],
    "connection_error": [
        r"ConnectionRefused",
        r"Connection refused",
        r"ConnectionReset",
        r"BrokenPipe",
        r"EOFError",
        r"socket\.timeout",
    ],
    "wrong_output": [
        r"wrong",
        r"incorrect",
        r"fail",
        r"denied",
        r"VERIFICATION FAILED",
    ],
    "math_error": [
        r"ZeroDivisionError",
        r"OverflowError",
        r"not invertible",
        r"gcd.*!=.*1",
        r"singular matrix",
    ],
}

# Error type -> decision_tree trigger mapping
ERROR_TO_TRIGGER = {
    "parse_error": None,           # Fix code directly, no decision_tree needed
    "type_error": None,            # Fix code directly
    "z3_unsat": "z3_unsat",        # decision_tree: rev/z3_unsat
    "timeout": "solve_failure",    # decision_tree: rev/solver_fallback
    "connection_error": "remote_failure",  # decision_tree: pwn/remote_failure
    "wrong_output": "solve_failure",
    "math_error": "math_failure",  # decision_tree: crypto/math_failure
    "unknown": "solve_failure",
}

# Error type -> agent mapping
ERROR_TO_AGENT = {
    "z3_unsat": "rev",
    "timeout": "rev",
    "connection_error": "pwn",
    "wrong_output": "rev",
    "math_error": "crypto",
    "solve_failure": "rev",
}


def classify_error(output: str, returncode: int = 1) -> dict:
    """Classify error from solve.py output."""
    result = {
        "error_type": "unknown",
        "matched_pattern": None,
        "has_flag": False,
        "flag": None,
        "suggestion": None,
    }

    # Check for flag first
    flag_match = FLAG_RE.search(output)
    if flag_match:
        result["has_flag"] = True
        result["flag"] = flag_match.group(1)
        result["error_type"] = "success"
        return result

    # Check for FLAG_FOUND marker
    if "FLAG_FOUND" in output:
        result["error_type"] = "success"
        result["has_flag"] = True
        # Try to extract flag after FLAG_FOUND
        idx = output.index("FLAG_FOUND")
        rest = output[idx:]
        flag_match = FLAG_RE.search(rest)
        if flag_match:
            result["flag"] = flag_match.group(1)
        return result

    # Classify by pattern matching
    for error_type, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, output, re.I):
                result["error_type"] = error_type
                result["matched_pattern"] = pattern
                break
        if result["error_type"] != "unknown":
            break

    # Generate suggestion
    trigger = ERROR_TO_TRIGGER.get(result["error_type"])
    if trigger:
        agent = ERROR_TO_AGENT.get(result["error_type"], "rev")
        result["suggestion"] = {
            "action": "decision_tree",
            "command": f"python tools/decision_tree.py next --agent {agent} --trigger {trigger}",
            "agent": agent,
            "trigger": trigger,
        }
    elif result["error_type"] in ("parse_error", "type_error"):
        result["suggestion"] = {
            "action": "fix_code",
            "description": "Fix the Python error in solve.py directly",
        }

    return result


# ============================================================================
# Run Loop
# ============================================================================

def run_solve(challenge_dir: str, timeout: int = 120, mode: str = "local") -> dict:
    """Run solve.py once and return structured result."""
    cdir = Path(challenge_dir)
    solve_py = cdir / "solve.py"

    if not solve_py.exists():
        return {"success": False, "error_type": "no_solve_py", "output": "solve.py not found"}

    env = os.environ.copy()
    env["CHALLENGE_DIR"] = str(cdir.resolve())

    cmd = ["python", str(solve_py)]
    if mode == "remote":
        cmd.append("--remote")

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=env, cwd=str(cdir),
        )
        output = r.stdout + "\n" + r.stderr
        classification = classify_error(output, r.returncode)
        classification["output"] = output[-2000:]  # Truncate for token efficiency
        classification["returncode"] = r.returncode
        return classification

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error_type": "timeout",
            "output": f"Timed out after {timeout}s",
            "suggestion": {
                "action": "decision_tree",
                "command": f"python tools/decision_tree.py next --agent rev --trigger solve_failure",
            },
        }


def run_loop(challenge_dir: str, max_retries: int = 3, timeout: int = 120) -> dict:
    """Run solve.py up to max_retries times, recording failures."""
    cdir = Path(challenge_dir)
    failures_file = cdir / "memory" / "failures.md"
    failures_file.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for attempt in range(1, max_retries + 1):
        print(f"\n[solve_loop] Attempt {attempt}/{max_retries}")
        result = run_solve(challenge_dir, timeout)
        results.append(result)

        if result.get("has_flag") or result.get("error_type") == "success":
            print(f"[solve_loop] FLAG FOUND: {result.get('flag', '???')}")
            return {"success": True, "flag": result.get("flag"), "attempts": attempt, "results": results}

        # Record failure
        error_type = result.get("error_type", "unknown")
        print(f"[solve_loop] Attempt {attempt} failed: {error_type}")

        # Append to failures.md
        with open(failures_file, "a", encoding="utf-8") as f:
            f.write(f"\n## Attempt {attempt} - {datetime.now().isoformat()}\n")
            f.write(f"- Error type: {error_type}\n")
            f.write(f"- Pattern: {result.get('matched_pattern', 'N/A')}\n")
            output_snippet = result.get("output", "")[:300].replace("\n", "\n  ")
            f.write(f"- Output: {output_snippet}\n")

        # Get decision_tree suggestion if applicable
        if result.get("suggestion", {}).get("action") == "decision_tree":
            trigger = result["suggestion"].get("trigger", "solve_failure")
            agent = result["suggestion"].get("agent", "rev")
            try:
                dt_env = os.environ.copy()
                dt_env["CHALLENGE_DIR"] = str(cdir.resolve())
                dt_result = subprocess.run(
                    ["python", "tools/decision_tree.py", "next",
                     "--agent", agent, "--trigger", trigger],
                    capture_output=True, text=True, timeout=10, env=dt_env,
                )
                if dt_result.returncode == 0:
                    dt_json = json.loads(dt_result.stdout)
                    result["decision_tree"] = dt_json
                    print(f"[solve_loop] Decision tree: {dt_json.get('action')} - {dt_json.get('description', '')[:80]}")

                    # Record the attempt
                    subprocess.run(
                        ["python", "tools/decision_tree.py", "record",
                         "--agent", agent, "--trigger", trigger,
                         "--action-id", dt_json.get("action", "unknown")],
                        capture_output=True, timeout=10, env=dt_env,
                    )
            except Exception as e:
                print(f"[solve_loop] Decision tree error: {e}")

        # Same error type 3 times → break and escalate
        same_errors = [r for r in results if r.get("error_type") == error_type]
        if len(same_errors) >= 3:
            print(f"[solve_loop] 3x same error ({error_type}) → escalating")
            break

    return {
        "success": False,
        "attempts": len(results),
        "last_error": results[-1].get("error_type", "unknown"),
        "results": results,
        "escalation": f"3+ failures — switch approach or WebSearch",
    }


# ============================================================================
# CLI
# ============================================================================

def cmd_run(args):
    result = run_loop(args.challenge_dir, args.max_retries, args.timeout)
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))


def cmd_classify(args):
    result = classify_error(args.output, 1)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_suggest(args):
    trigger = ERROR_TO_TRIGGER.get(args.error_type, "solve_failure")
    if not trigger:
        print(json.dumps({"action": "fix_code", "error_type": args.error_type}))
        return

    agent = args.agent or ERROR_TO_AGENT.get(args.error_type, "rev")
    env = os.environ.copy()
    env["CHALLENGE_DIR"] = str(Path(args.challenge_dir).resolve())
    r = subprocess.run(
        ["python", "tools/decision_tree.py", "next", "--agent", agent, "--trigger", trigger],
        capture_output=True, text=True, timeout=10, env=env,
    )
    if r.returncode == 0:
        print(r.stdout)
    else:
        print(json.dumps({"error": "decision_tree failed", "stderr": r.stderr[:200]}))


def main():
    p = argparse.ArgumentParser(description="Automated solve-retry with decision_tree integration")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("run", help="Run solve.py with retry loop")
    s.add_argument("challenge_dir")
    s.add_argument("--max-retries", type=int, default=3)
    s.add_argument("--timeout", type=int, default=120)

    s = sub.add_parser("classify", help="Classify error from output text")
    s.add_argument("challenge_dir")
    s.add_argument("--output", required=True, help="Output text to classify")

    s = sub.add_parser("suggest", help="Get decision_tree suggestion for error type")
    s.add_argument("challenge_dir")
    s.add_argument("--agent", default=None)
    s.add_argument("--error-type", required=True,
                   choices=list(ERROR_TO_TRIGGER.keys()) + ["unknown"])

    args = p.parse_args()
    {"run": cmd_run, "classify": cmd_classify, "suggest": cmd_suggest}[args.cmd](args)


if __name__ == "__main__":
    main()
