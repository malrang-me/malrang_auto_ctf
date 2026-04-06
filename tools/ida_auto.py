#!/usr/bin/env python3
"""
IDA Pro Auto-Launcher for CTF Pipeline
======================================
Automatically opens a binary in IDA Pro with MCP RPC server enabled.

Usage:
  ida_auto.py open <binary_path>     # Open binary in IDA, auto-start MCP RPC
  ida_auto.py check                  # Check if IDA RPC is responding
  ida_auto.py setup                  # One-time: install IDA MCP plugin

Flow:
  1. reverser agent calls: python tools/ida_auto.py open challenges/foo/binary
  2. This script launches IDA64 with -A (auto-analysis) + startup script
  3. Startup script loads the MCP plugin and starts HTTP RPC on :13337
  4. ida-pro-mcp MCP server (already in .mcp.json) connects via RPC
  5. reverser uses IDA MCP tools transparently

Requirements:
  - IDA Pro 9.0 installed
  - ida-pro-mcp pip package installed (pip install ida-pro-mcp)
  - One-time: run `python tools/ida_auto.py setup` to install plugin
"""

import argparse
import http.client
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

def _get_ida_path():
    """Get IDA path, handling both Windows and WSL environments."""
    import platform
    if platform.system() == "Linux" and "microsoft" in platform.release().lower():
        # WSL: use Windows exe via /mnt/c path
        wsl_path = "/mnt/c/Program Files/IDA Professional 9.0/ida64.exe"
        if os.path.exists(wsl_path):
            return wsl_path
    win_path = r"C:\Program Files\IDA Professional 9.0\ida64.exe"
    if os.path.exists(win_path):
        return win_path
    return win_path  # fallback, will error later

IDA_PATH = _get_ida_path()
IDA_RPC_PORT = 13337

def _get_rpc_host():
    """Get IDA RPC host. WSL needs Windows gateway IP, not 127.0.0.1."""
    import platform
    if platform.system() == "Linux" and "microsoft" in platform.release().lower():
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.strip().split()
                    if parts[1] == "00000000":  # default route
                        hex_ip = parts[2]
                        return ".".join(str(int(hex_ip[i:i+2], 16)) for i in (6,4,2,0))
        except Exception:
            pass
        # fallback: parse ip route
        try:
            import subprocess
            out = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=3)
            parts = out.stdout.strip().split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        except Exception:
            pass
    return "127.0.0.1"

IDA_RPC_HOST = _get_rpc_host()
STARTUP_SCRIPT = Path(__file__).parent / "ida_startup.py"


def check_rpc(timeout: float = 2.0) -> bool:
    """Check if IDA MCP RPC server is responding."""
    try:
        conn = http.client.HTTPConnection(IDA_RPC_HOST, IDA_RPC_PORT, timeout=timeout)
        # Send a minimal JSON-RPC request
        req = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05",
                       "capabilities": {},
                       "clientInfo": {"name": "ida_auto_check", "version": "1.0"}},
            "id": 1
        })
        conn.request("POST", "/mcp", req, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status == 200
    except Exception:
        return False


def create_startup_script():
    """Create IDAPython startup script that auto-enables MCP RPC."""
    script_content = '''# IDA Auto-Startup Script for MCP RPC
# This script is run by IDA on startup (-S flag) to enable MCP server.
import idaapi
import ida_auto

def start_mcp_after_analysis():
    """Start MCP server after auto-analysis completes."""
    class AnalysisHandler(idaapi.auto_empty_queue_t):
        def run(self):
            try:
                # Import and activate the MCP plugin
                import ida_mcp
                # The plugin registers itself; we just need to activate it
                plugin = idaapi.find_plugin("ida_mcp", True)
                if plugin:
                    idaapi.run_plugin(plugin, 0)
                    print("[ida_auto] MCP RPC server started on port 13337")
                else:
                    print("[ida_auto] WARNING: ida_mcp plugin not found. Run: python tools/ida_auto.py setup")
            except Exception as e:
                print(f"[ida_auto] Failed to start MCP: {e}")
            return False  # Don't re-queue

    handler = AnalysisHandler()
    handler.run()  # Try immediately (analysis may already be done)

# Wait for IDA to finish loading, then start MCP
idaapi.register_timer(3000, lambda: (start_mcp_after_analysis(), -1)[1])
'''
    STARTUP_SCRIPT.write_text(script_content)
    return STARTUP_SCRIPT


def open_binary(binary_path: str, wait_rpc: bool = True, timeout: int = 60) -> bool:
    """Open binary in IDA Pro with auto-analysis and MCP RPC.

    Args:
        binary_path: Path to the binary file
        wait_rpc: Whether to wait for RPC to become available
        timeout: Max seconds to wait for RPC

    Returns:
        True if IDA opened and RPC is ready, False otherwise
    """
    binary = Path(binary_path).resolve()
    if not binary.exists():
        print(f"[ida_auto] Binary not found: {binary}", file=sys.stderr)
        return False

    if not Path(IDA_PATH).exists():
        print(f"[ida_auto] IDA not found at: {IDA_PATH}", file=sys.stderr)
        return False

    # Check if RPC is already running (IDA might already be open)
    if check_rpc(timeout=1.0):
        print("[ida_auto] IDA MCP RPC already running")
        return True

    # Convert WSL paths to Windows format for IDA
    binary_for_ida = str(binary)
    if binary_for_ida.startswith("/mnt/c/"):
        binary_for_ida = "C:\\" + binary_for_ida[7:].replace("/", "\\")

    cmd = [
        IDA_PATH,
        "-A",
        str(binary_for_ida)
    ]

    print(f"[ida_auto] Launching IDA: {binary.name}")
    try:
        # Start IDA as detached process with MCP autostart env var
        env = os.environ.copy()
        env["IDA_MCP_AUTOSTART"] = "1"
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "env": env}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(cmd, **kwargs)
    except Exception as e:
        print(f"[ida_auto] Failed to launch IDA: {e}", file=sys.stderr)
        return False

    if not wait_rpc:
        print("[ida_auto] IDA launched (not waiting for RPC)")
        return True

    # Wait for RPC to become available
    print(f"[ida_auto] Waiting for RPC (max {timeout}s)...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        if check_rpc(timeout=2.0):
            elapsed = time.time() - start
            print(f" ready ({elapsed:.1f}s)")
            return True
        print(".", end="", flush=True)
        time.sleep(3)

    print(f" TIMEOUT after {timeout}s")
    print("[ida_auto] IDA may still be analyzing. Try again in a few seconds.")
    return False


def get_loaded_binary() -> str:
    """Get the currently loaded binary path in IDA via RPC."""
    try:
        conn = http.client.HTTPConnection(IDA_RPC_HOST, IDA_RPC_PORT, timeout=5)
        req = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "idb_meta", "arguments": {}},
            "id": 1
        })
        conn.request("POST", "/mcp", req, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        # Extract filename from response
        content = data.get("result", {}).get("content", [])
        if content:
            text = content[0].get("text", "")
            for line in text.split("\n"):
                if "input_file" in line.lower() or "file" in line.lower():
                    # Try to extract path
                    if ":" in line:
                        return line.split(":", 1)[1].strip()
            return text[:200]
        return ""
    except Exception:
        return ""


def load_binary(binary_path: str) -> bool:
    """Load a binary into the running IDA instance.

    If IDA has a different binary loaded, close it and open the new one.
    Returns True if the correct binary is loaded.
    """
    binary = Path(binary_path).resolve()
    if not binary.exists():
        print(f"[ida_auto] Binary not found: {binary}", file=sys.stderr)
        return False

    if not check_rpc(timeout=2.0):
        print("[ida_auto] IDA MCP not responding. Open IDA and press Ctrl+Alt+M first.")
        return False

    # Check what's currently loaded
    current = get_loaded_binary()
    binary_name = binary.name

    if binary_name.lower() in current.lower():
        print(f"[ida_auto] Correct binary already loaded: {binary_name}")
        return True

    print(f"[ida_auto] Currently loaded: {current}")
    print(f"[ida_auto] Need to load: {binary_name}")

    # Convert to Windows path for IDA
    binary_win = str(binary)
    if binary_win.startswith("/mnt/c/"):
        binary_win = "C:\\" + binary_win[7:].replace("/", "\\")

    # Use IDA's py_eval to open the new binary
    try:
        conn = http.client.HTTPConnection(IDA_RPC_HOST, IDA_RPC_PORT, timeout=30)
        # Use idaapi.open_database to load new file
        code = f'import idaapi; idaapi.open_database("{binary_win.replace(chr(92), chr(92)*2)}", True)'
        req = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "py_eval", "arguments": {"code": code}},
            "id": 1
        })
        conn.request("POST", "/mcp", req, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()

        if "error" in data:
            print(f"[ida_auto] Failed to load via API: {data['error']}")
            # Fallback: close IDA and reopen with new binary
            print(f"[ida_auto] Fallback: Please open {binary_name} in IDA manually")
            return False

        print(f"[ida_auto] Binary loaded: {binary_name}")
        return True
    except Exception as e:
        print(f"[ida_auto] Load failed: {e}")
        return False


def setup():
    """One-time setup: install IDA MCP plugin."""
    try:
        # Use ida-pro-mcp's built-in installer
        subprocess.run(
            [sys.executable, "-m", "ida_pro_mcp", "--install"],
            check=True
        )
        print("[ida_auto] IDA MCP plugin installed successfully")
        print("[ida_auto] Restart IDA if it's currently running")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ida_auto] Plugin installation failed: {e}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("[ida_auto] ida-pro-mcp not installed. Run: pip install ida-pro-mcp", file=sys.stderr)
        return False


def main():
    p = argparse.ArgumentParser(description="IDA Pro Auto-Launcher for CTF Pipeline")
    sub = p.add_subparsers(dest="cmd")

    op = sub.add_parser("open", help="Open binary in IDA with MCP RPC")
    op.add_argument("binary", help="Path to binary file")
    op.add_argument("--no-wait", action="store_true", help="Don't wait for RPC")
    op.add_argument("--timeout", type=int, default=60, help="RPC wait timeout (seconds)")

    ld = sub.add_parser("load", help="Load binary into running IDA (switch if different)")
    ld.add_argument("binary", help="Path to binary file")

    sub.add_parser("check", help="Check if IDA RPC is responding")
    sub.add_parser("setup", help="One-time: install IDA MCP plugin")

    args = p.parse_args()

    if args.cmd == "open":
        ok = open_binary(args.binary, wait_rpc=not args.no_wait, timeout=args.timeout)
        sys.exit(0 if ok else 1)
    elif args.cmd == "load":
        ok = load_binary(args.binary)
        sys.exit(0 if ok else 1)
    elif args.cmd == "check":
        if check_rpc():
            print("[ida_auto] IDA MCP RPC is responding")
            sys.exit(0)
        else:
            print("[ida_auto] IDA MCP RPC is NOT responding")
            sys.exit(1)
    elif args.cmd == "setup":
        ok = setup()
        sys.exit(0 if ok else 1)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
