#!/usr/bin/env python3
"""
ops.py — Consolidated operations (replaces 5 PowerShell scripts)

Usage:
  python tools/ops.py scaffold <name> --category <cat> [--remote "host port"] [--platform dreamhack]
  python tools/ops.py intake <name> --category <cat> [--zip <path>]
  python tools/ops.py run <challenge_dir> [--mode remote] [--host H] [--port P]
  python tools/ops.py gate <challenge_dir>
  python tools/ops.py metrics <challenge_dir> --event <start|attempt|success|fail|gate> [--branch B] [--summary S]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_DIR = PROJ_ROOT / "challenges"
METRICS_FILE = PROJ_ROOT / "metrics" / "ctf_runs.jsonl"


# ---------------------------------------------------------------------------
# scaffold
# ---------------------------------------------------------------------------
def set_terminal_title(name: str):
    """Set terminal tab title to current challenge name."""
    import sys
    sys.stderr.write(f"\033]0;CTF: {name}\007")
    sys.stderr.flush()


def cmd_scaffold(args):
    set_terminal_title(args.name)
    chal_dir = CHALLENGES_DIR / args.name
    if chal_dir.exists():
        print(f"[!] Already exists: {chal_dir}")
        return

    chal_dir.mkdir(parents=True)
    (chal_dir / "memory").mkdir()

    # meta.yaml
    host, port = "", ""
    if args.remote:
        parts = args.remote.split()
        host = parts[0] if len(parts) > 0 else ""
        port = parts[1] if len(parts) > 1 else ""

    (chal_dir / "meta.yaml").write_text(f"""name: {args.name}
category: {args.category}
platform: {args.platform}
remote_host: "{host}"
remote_port: "{port}"
status: init
created_at: {datetime.now().isoformat()}
""", encoding="utf-8")

    # Entry point
    entry = "exploit.py" if args.category in ("pwn", "web") else "solve.py"
    if args.category in ("pwn", "web"):
        (chal_dir / entry).write_text("""#!/usr/bin/env python3
import os
from pwn import *

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", "1337"))

def exploit():
    # r = remote(HOST, PORT)
    # r = process("./binary")
    pass

if __name__ == "__main__":
    exploit()
""", encoding="utf-8")
    else:
        (chal_dir / entry).write_text("""#!/usr/bin/env python3
import os

HOST = os.environ.get("HOST", "")
PORT = os.environ.get("PORT", "")

def solve():
    pass

if __name__ == "__main__":
    solve()
""", encoding="utf-8")

    # Memory files
    for mf in ["recon.md", "strategy.md", "discoveries.md", "failures.md"]:
        (chal_dir / "memory" / mf).write_text(f"# {args.name} - {mf.replace('.md','')}\n", encoding="utf-8")

    print(f"[scaffold] Created: {chal_dir}")
    print(f"  entry: {entry}, category: {args.category}")


# ---------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------
def cmd_intake(args):
    chal_dir = CHALLENGES_DIR / args.name
    downloads = PROJ_ROOT / "_downloads"

    # Find zip
    zip_path = None
    if args.zip:
        zip_path = Path(args.zip)
    else:
        if downloads.exists():
            zips = sorted(downloads.glob("*.zip"), key=lambda f: f.stat().st_mtime, reverse=True)
            if zips:
                zip_path = zips[0]
                print(f"[intake] Auto-detected: {zip_path}")

    # Scaffold if needed
    if not chal_dir.exists():
        class FakeArgs:
            name = args.name
            category = args.category
            remote = ""
            platform = "dreamhack"
        cmd_scaffold(FakeArgs())

    # Extract zip
    if zip_path and zip_path.exists():
        print(f"[intake] Extracting: {zip_path}")
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(chal_dir)
        print(f"[intake] Extracted to: {chal_dir}")
    else:
        print("[intake] No zip found, scaffold only")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def _parse_meta(chal_dir: Path) -> dict:
    """Parse meta.yaml and return a dict of key fields."""
    meta = chal_dir / "meta.yaml"
    result = {"host": "", "port": "", "timeout": 300}
    if not meta.exists():
        return result
    content = meta.read_text(encoding="utf-8")
    m = re.search(r'remote_host:\s*"?([^"\n]*)"?', content)
    if m:
        result["host"] = m.group(1).strip()
    m = re.search(r'remote_port:\s*"?([^"\n]*)"?', content)
    if m:
        result["port"] = m.group(1).strip()
    m = re.search(r'timeout:\s*(\d+)', content)
    if m:
        result["timeout"] = int(m.group(1))
    return result


def cmd_run(args):
    set_terminal_title(Path(args.path).name)
    chal_dir = Path(args.path)
    if not chal_dir.exists():
        chal_dir = CHALLENGES_DIR / args.path
    if not chal_dir.exists():
        print(f"[error] Not found: {chal_dir}")
        sys.exit(1)

    # Find entry point: exploit.py > solve.py > solve.sage
    entry = None
    for f in ["exploit.py", "solve.py", "solve.sage"]:
        if (chal_dir / f).exists():
            entry = chal_dir / f
            break
    if not entry:
        print("[error] No solve.py, exploit.py, or solve.sage found")
        sys.exit(1)

    # Determine interpreter for .sage files
    is_sage = entry.suffix == ".sage"

    # Get remote info from args or meta.yaml
    meta = _parse_meta(chal_dir)
    host = args.host or (meta["host"] if args.mode == "remote" else "")
    port = args.port or (meta["port"] if args.mode == "remote" else "")
    timeout = args.timeout or meta["timeout"]

    env = os.environ.copy()
    if host:
        env["HOST"] = host
    if port:
        env["PORT"] = port

    # Build command
    if is_sage:
        cmd = ["wsl", "sage", str(entry).replace("\\", "/")]
    else:
        cmd = [sys.executable, str(entry)]

    print(f"[run] {entry.name} mode={args.mode} host={host} port={port} timeout={timeout}s")

    # Run with output capture to LAST_RUN.log
    log_file = chal_dir / "LAST_RUN.log"
    try:
        result = subprocess.run(
            cmd,
            cwd=str(chal_dir),
            env=env,
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = result.stdout + (result.stderr or "")
        log_file.write_text(output, encoding="utf-8")
        print(output)
        if result.returncode != 0:
            print(f"[run] Exit code: {result.returncode}")
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        print(f"[run] TIMEOUT after {timeout}s")
        log_file.write_text(f"TIMEOUT after {timeout}s\n", encoding="utf-8")
        sys.exit(124)


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------
def cmd_gate(args):
    chal_dir = Path(args.path)
    if not chal_dir.exists():
        chal_dir = CHALLENGES_DIR / args.path
    if not chal_dir.exists():
        print(f"[error] Not found: {chal_dir}")
        sys.exit(1)

    checks = []
    passed = True

    # 1. meta.yaml
    if (chal_dir / "meta.yaml").exists():
        checks.append("[PASS] meta.yaml exists")
    else:
        checks.append("[FAIL] meta.yaml missing")
        passed = False

    # 2. Solver exists and non-trivial
    solver = None
    for f in ["exploit.py", "solve.py"]:
        if (chal_dir / f).exists():
            solver = chal_dir / f
            break
    if solver and solver.stat().st_size > 200:
        checks.append(f"[PASS] {solver.name} ({solver.stat().st_size} bytes)")
    else:
        checks.append(f"[FAIL] solver missing or too small")
        passed = False

    # 3. Memory files populated
    for mf in ["recon.md", "strategy.md"]:
        fp = chal_dir / "memory" / mf
        if fp.exists() and fp.stat().st_size > 50:
            checks.append(f"[PASS] memory/{mf} populated")
        else:
            checks.append(f"[FAIL] memory/{mf} empty or missing")
            passed = False

    # 4. Checkpoint
    cp = chal_dir / "checkpoint.json"
    if cp.exists():
        data = json.loads(cp.read_text(encoding="utf-8"))
        checks.append(f"[PASS] checkpoint: {data.get('status','?')}")
    else:
        checks.append("[WARN] checkpoint.json missing")

    print("\n".join(checks))
    print(f"\n{'GATE PASSED' if passed else 'GATE FAILED'}")
    sys.exit(0 if passed else 1)


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------
def cmd_metrics(args):
    chal_dir = Path(args.path)
    if not chal_dir.exists():
        chal_dir = CHALLENGES_DIR / args.path

    name = chal_dir.name
    category = ""
    meta = chal_dir / "meta.yaml"
    if meta.exists():
        content = meta.read_text(encoding="utf-8")
        m = re.search(r'category:\s*(\S+)', content)
        if m:
            category = m.group(1)

    METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry_data = {
        "timestamp": datetime.now().isoformat(),
        "challenge": name,
        "category": category,
        "event": args.event,
        "branch": args.branch or "",
        "summary": args.summary or "",
    }
    # Extra fields for success events
    if args.event == "success":
        if args.elapsed:
            entry_data["elapsed_sec"] = args.elapsed
        if args.attempts:
            entry_data["attempts"] = args.attempts
        if args.failures:
            entry_data["failures"] = args.failures
        if args.technique:
            entry_data["technique"] = args.technique
        if args.next_estimate:
            entry_data["next_estimate_sec"] = args.next_estimate

    entry = json.dumps(entry_data, ensure_ascii=False)
    with open(METRICS_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(f"[metrics] {args.event}: {name}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("scaffold")
    p.add_argument("name")
    p.add_argument("--category", required=True)
    p.add_argument("--remote", default="")
    p.add_argument("--platform", default="dreamhack")

    p = sub.add_parser("intake")
    p.add_argument("name")
    p.add_argument("--category", required=True)
    p.add_argument("--zip", default="")

    p = sub.add_parser("run")
    p.add_argument("path")
    p.add_argument("--mode", default="local", choices=["local", "remote"])
    p.add_argument("--host", default="")
    p.add_argument("--port", default="")
    p.add_argument("--timeout", type=int, default=0, help="Timeout in seconds (0 = use meta.yaml or default 300)")

    p = sub.add_parser("gate")
    p.add_argument("path")

    p = sub.add_parser("metrics")
    p.add_argument("path")
    p.add_argument("--event", required=True)
    p.add_argument("--branch", default="")
    p.add_argument("--summary", default="")
    p.add_argument("--elapsed", type=int, default=0, help="Solve time in seconds")
    p.add_argument("--attempts", type=int, default=0, help="Total solve attempts")
    p.add_argument("--failures", type=int, default=0, help="Failed approach count")
    p.add_argument("--technique", default="", help="Key technique used")
    p.add_argument("--next-estimate", type=int, default=0, help="Predicted time for similar challenge (seconds)")

    args = parser.parse_args()
    if args.cmd == "scaffold":
        cmd_scaffold(args)
    elif args.cmd == "intake":
        cmd_intake(args)
    elif args.cmd == "run":
        cmd_run(args)
    elif args.cmd == "gate":
        cmd_gate(args)
    elif args.cmd == "metrics":
        cmd_metrics(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
