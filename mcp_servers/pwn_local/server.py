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

    lines = out.splitlines()

    if pattern:
        filtered = [ln for ln in lines if pattern.lower() in ln.lower()]
        return "\n".join(filtered) if filtered else f"no match for pattern: {pattern}"

    # Auto-truncate: if output > 500 lines, keep function headers + key sections
    MAX_LINES = 500
    if len(lines) > MAX_LINES:
        head = lines[:80]  # headers + early functions
        # Extract all function entry points
        func_lines = [ln for ln in lines if ln.strip().endswith(">:")]
        # Extract cmp/call/jmp instructions (most useful for RE)
        key_insns = [ln for ln in lines
                     if any(k in ln.lower() for k in ("call ", "cmp ", "test ", "jmp ", "je ", "jne ", "jle ", "jge "))]
        tail = lines[-30:]

        truncated = head
        truncated.append(f"\n[--- {len(lines)} total lines, showing function list + key instructions ---]")
        truncated.append(f"\n[FUNCTIONS ({len(func_lines)})]")
        truncated.extend(func_lines[:50])
        truncated.append(f"\n[KEY INSTRUCTIONS ({len(key_insns)} cmp/call/jmp)]")
        truncated.extend(key_insns[:200])
        truncated.append(f"\n[TAIL]")
        truncated.extend(tail)
        return "\n".join(truncated)

    return out


@mcp.tool(description="Run ROPGadget on an ELF and optionally filter by pattern")
def pwn_ropgadget(binary_path: str, pattern: str = "") -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"

    cmd = ["ROPGadget", "--binary", str(b)]
    out = _run(cmd, cwd=b.parent, timeout=90)

    lines = out.splitlines()
    if pattern:
        filtered = [ln for ln in lines if pattern.lower() in ln.lower()]
        return "\n".join(filtered) if filtered else f"no match for pattern: {pattern}"

    # Auto-truncate: keep first 300 gadgets + summary
    MAX_GADGETS = 300
    if len(lines) > MAX_GADGETS:
        return "\n".join(lines[:MAX_GADGETS]) + f"\n\n[... {len(lines) - MAX_GADGETS} more gadgets truncated. Use pattern filter to narrow.]"
    return out


@mcp.tool(description="Run strings on a binary with auto-truncation and optional pattern filter")
def pwn_strings(binary_path: str, pattern: str = "", max_lines: int = 100) -> str:
    b = _resolve_under_root(binary_path)
    if not b.exists():
        return f"binary not found: {b}"

    out = _run(["strings", "-a", str(b)], cwd=b.parent, timeout=30)
    lines = out.splitlines()

    if pattern:
        filtered = [ln for ln in lines if pattern.lower() in ln.lower()]
        return "\n".join(filtered[:max_lines]) if filtered else f"no match for pattern: {pattern}"

    # Auto-categorize strings for token efficiency
    flag_hints = [ln for ln in lines if any(p in ln for p in ["flag", "DH{", "CTF{", "FLAG{", "flag{"])]
    func_names = [ln for ln in lines if any(p in ln for p in ["gets", "strcpy", "sprintf", "system", "execve", "/bin/sh", "puts", "printf"])]
    interesting = [ln for ln in lines if any(p in ln for p in ["password", "secret", "key", "admin", "login", "token", "http"])]

    result = [f"[strings] {len(lines)} total strings from {b.name}"]
    if flag_hints:
        result.append(f"\n[FLAG HINTS ({len(flag_hints)})]")
        result.extend(flag_hints[:20])
    if func_names:
        result.append(f"\n[DANGEROUS FUNCTIONS ({len(func_names)})]")
        result.extend(func_names[:20])
    if interesting:
        result.append(f"\n[INTERESTING ({len(interesting)})]")
        result.extend(interesting[:20])

    # Add head/tail of all strings if nothing categorized
    if not (flag_hints or func_names or interesting):
        result.append(f"\n[FIRST {min(50, len(lines))} STRINGS]")
        result.extend(lines[:50])

    if len(lines) > max_lines:
        result.append(f"\n[... {len(lines) - max_lines} more. Use pattern param to filter.]")

    return "\n".join(result)


@mcp.tool(description="Execute solve.py with args and return combined log. timeout_sec up to 600 for brute/canary.")
def pwn_run_solve(
    challenge_dir: str,
    args: str = "",
    timeout_sec: int = 90,
    use_wsl: bool = False,
) -> str:
    """Run challenge solver.

    timeout_sec: default 90s. For canary/ASLR brute force or fork-server
    interactions, pass up to 600 (10 min).

    use_wsl: when True, .py solvers are launched via `wsl python3` so the
    binary loads its real interpreter (and provided libc via patchelf).
    Mandatory for any solver that does process(elf.path) on Linux ELFs.
    """
    cdir = _resolve_under_root(challenge_dir)

    # Cap at 10 minutes regardless
    timeout_sec = max(1, min(int(timeout_sec), 600))

    # Find solver: exploit.py > solve.py > solve.sage
    solve = None
    for name in ["exploit.py", "solve.py", "solve.sage"]:
        candidate = cdir / name
        if candidate.exists():
            solve = candidate
            break

    if solve is None:
        return f"No solver found (tried exploit.py, solve.py, solve.sage) in: {cdir}"

    # Choose interpreter based on file type
    if solve.suffix == ".sage":
        argv = ["wsl", "sage", str(solve).replace("\\", "/")]
    elif use_wsl or (cdir / "use_wsl").exists():
        # Translate Windows path to /mnt/<drive>/...
        s = str(solve.resolve())
        if len(s) >= 2 and s[1] == ":":
            wsl_path = f"/mnt/{s[0].lower()}{s[2:].replace(chr(92), '/')}"
        else:
            wsl_path = s.replace("\\", "/")
        argv = ["wsl", "--", "python3", wsl_path]
    else:
        argv = ["python", str(solve)]

    if args.strip():
        argv.extend(shlex.split(args))

    return _run(argv, cwd=cdir, timeout=timeout_sec)


if __name__ == "__main__":
    mcp.run(transport="stdio")
