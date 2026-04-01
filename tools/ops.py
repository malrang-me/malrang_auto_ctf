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
def cmd_scaffold(args):
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
def cmd_run(args):
    chal_dir = Path(args.path)
    if not chal_dir.exists():
        chal_dir = CHALLENGES_DIR / args.path
    if not chal_dir.exists():
        print(f"[error] Not found: {chal_dir}")
        sys.exit(1)

    # Find entry point
    entry = None
    for f in ["exploit.py", "solve.py"]:
        if (chal_dir / f).exists():
            entry = chal_dir / f
            break
    if not entry:
        print("[error] No solve.py or exploit.py found")
        sys.exit(1)

    # Get remote info
    host, port = args.host, args.port
    if args.mode == "remote" and not host:
        meta = chal_dir / "meta.yaml"
        if meta.exists():
            content = meta.read_text(encoding="utf-8")
            m = re.search(r'remote_host:\s*"?([^"\n]*)"?', content)
            if m:
                host = m.group(1).strip()
            m = re.search(r'remote_port:\s*"?([^"\n]*)"?', content)
            if m:
                port = m.group(1).strip()

    env = os.environ.copy()
    if host:
        env["HOST"] = host
    if port:
        env["PORT"] = port

    print(f"[run] {entry.name} mode={args.mode} host={host} port={port}")
    result = subprocess.run(
        [sys.executable, str(entry)],
        cwd=str(chal_dir),
        env=env,
        timeout=300,
    )
    sys.exit(result.returncode)


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
    entry = json.dumps({
        "timestamp": datetime.now().isoformat(),
        "challenge": name,
        "category": category,
        "event": args.event,
        "branch": args.branch or "",
        "summary": args.summary or "",
    })
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

    p = sub.add_parser("gate")
    p.add_argument("path")

    p = sub.add_parser("metrics")
    p.add_argument("path")
    p.add_argument("--event", required=True)
    p.add_argument("--branch", default="")
    p.add_argument("--summary", default="")

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
