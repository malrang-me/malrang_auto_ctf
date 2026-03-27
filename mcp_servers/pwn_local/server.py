#!/usr/bin/env python3
"""Local MCP server for common pwn workflow commands.

This server is intentionally minimal and workspace-scoped.
Use PWN_MCP_ROOT to constrain all file paths.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pwn-local")
ROOT = Path(os.environ.get("PWN_MCP_ROOT", os.getcwd())).resolve()


def _resolve_under_root(path_str: str) -> Path:
    p = Path(path_str)
    if not p.is_absolute():
        p = (ROOT / p).resolve()
    else:
        p = p.resolve()

    try:
        p.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"Path escapes root: {p} (root: {ROOT})") from exc

    return p


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 25) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout or ""
    err = proc.stderr or ""
    return (
        f"$ {' '.join(shlex.quote(x) for x in cmd)}\n"
        f"[exit={proc.returncode}]\n"
        f"[stdout]\n{out}\n"
        f"[stderr]\n{err}"
    )


@mcp.tool(description="Run checksec-style summary for an ELF using pwntools")
def pwn_checksec(binary_path: str) -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"

    code = (
        "from pwn import ELF; "
        "e=ELF(r'''{}'''); "
        "print(e.checksec())".format(str(b).replace("'", "\\'"))
    )
    return _run(["python", "-c", code], cwd=b.parent)


@mcp.tool(description="Run readelf -h -l -S for an ELF")
def pwn_readelf(binary_path: str) -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"
    return _run(["readelf", "-h", "-l", "-S", str(b)], cwd=b.parent)


@mcp.tool(description="Run objdump disassembly and optional grep-like pattern filter")
def pwn_objdump(binary_path: str, pattern: str = "") -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"

    out = _run(["objdump", "-d", "-M", "intel", str(b)], cwd=b.parent, timeout=60)
    if not pattern:
        return out

    lines = out.splitlines()
    filtered = [ln for ln in lines if pattern.lower() in ln.lower()]
    return "\n".join(filtered) if filtered else f"no match for pattern: {pattern}"


@mcp.tool(description="Run ROPGadget on an ELF and optionally filter by pattern")
def pwn_ropgadget(binary_path: str, pattern: str = "") -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"

    cmd = ["ROPGadget", "--binary", str(b)]
    out = _run(cmd, cwd=b.parent, timeout=90)
    if not pattern:
        return out

    filtered = [ln for ln in out.splitlines() if pattern.lower() in ln.lower()]
    return "\n".join(filtered) if filtered else f"no match for pattern: {pattern}"


@mcp.tool(description="Execute solve.py with args and return combined log")
def pwn_run_solve(
    challenge_dir: str,
    args: str = "",
    timeout_sec: int = 60,
) -> str:
    cdir = _resolve_under_root(challenge_dir)
    solve = cdir / "solve.py"
    if not solve.exists():
        return f"solve.py not found in: {cdir}"

    argv = ["python", str(solve)]
    if args.strip():
        argv.extend(shlex.split(args))

    return _run(argv, cwd=cdir, timeout=timeout_sec)


if __name__ == "__main__":
    mcp.run(transport="stdio")
