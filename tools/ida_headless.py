#!/usr/bin/env python3
"""
IDA Pro headless decompiler + metadata dumper.

Runs IDA64 in headless mode (-A auto-analysis) with an IDAPython post-script
that dumps decompilation and/or metadata in ONE invocation. Avoids the per-call
RPC token overhead of the IDA MCP server.

Subcommands:
  dump      — decompile all (or filtered) functions → decompiled/<name>.c
  metadata  — dump functions/imports/strings/xrefs → ida_meta.json
  patch     — run a user IDAPython script against the binary
  full      — dump + metadata (one IDA invocation, recommended)

Usage:
  python tools/ida_headless.py full <binary> --challenge-dir challenges/<name>
  python tools/ida_headless.py dump <binary> --out challenges/<name>/decompiled
  python tools/ida_headless.py metadata <binary> --out challenges/<name>/ida_meta.json
  python tools/ida_headless.py patch <binary> --script my_patch.py -o patched

After `full`, read individual functions with Read/Grep — DO NOT call the IDA MCP
decompile tool on functions already present in decompiled/.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# IDA discovery (reuses the same logic as tools/ida_auto.py)
# ---------------------------------------------------------------------------

def _get_ida_path() -> str:
    """Find ida64 executable (Windows native or from WSL)."""
    import platform
    if platform.system() == "Linux" and "microsoft" in platform.release().lower():
        wsl_path = "/mnt/c/Program Files/IDA Professional 9.0/ida64.exe"
        if os.path.exists(wsl_path):
            return wsl_path
    win_path = r"C:\Program Files\IDA Professional 9.0\ida64.exe"
    if os.path.exists(win_path):
        return win_path
    # Env override
    env_path = os.environ.get("IDA_PATH") or os.environ.get("IDA64_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    return win_path  # fallback, will error later with a clear message


IDA_PATH = _get_ida_path()


def _abs(path: str) -> Path:
    return Path(path).expanduser().resolve()


# ---------------------------------------------------------------------------
# IDAPython scripts (written to temp files and passed via -S)
# ---------------------------------------------------------------------------

# Dump script — writes every function to <OUT_DIR>/<func>.c + summary.json.
# Uses env vars (IDA_DUMP_OUT, IDA_DUMP_FILTER) for parameters because IDA's
# -S only passes positional script args, and they are awkward to quote on Windows.
DUMP_SCRIPT = r'''
import os, json, re, traceback
import idaapi, idautils, idc

# Wait for auto-analysis to finish before touching anything.
idaapi.auto_wait()

try:
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler not available")
    HAVE_HEXRAYS = True
except Exception as e:
    HAVE_HEXRAYS = False
    _hx_err = str(e)

out_dir = os.environ.get("IDA_DUMP_OUT", "decompiled")
try:
    os.makedirs(out_dir, exist_ok=True)
except Exception:
    pass

name_filter = os.environ.get("IDA_DUMP_FILTER", "").strip()
allow = set()
if name_filter:
    for part in name_filter.split(","):
        part = part.strip()
        if part:
            allow.add(part)

def _safe_name(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)[:80]

summary = []
skipped = 0
failed = 0

for ea in idautils.Functions():
    name = idc.get_func_name(ea) or "sub_%x" % ea
    # When a filter is provided, only dump matching names.
    if allow and name not in allow and not any(p in name for p in allow):
        skipped += 1
        continue
    # Skip thunks and library imports unless explicitly requested.
    flags = idc.get_func_flags(ea)
    if not allow and flags is not None and (flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)):
        skipped += 1
        continue

    entry = {"name": name, "addr": "0x%x" % ea}
    fn_path = os.path.join(out_dir, _safe_name(name) + ".c")

    if HAVE_HEXRAYS:
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                raise RuntimeError("decompile returned None")
            code = str(cfunc)
            with open(fn_path, "w", encoding="utf-8") as f:
                f.write(code)
            entry["size"] = len(code)
            entry["lines"] = code.count("\n") + 1
        except Exception as e:
            failed += 1
            entry["error"] = str(e)[:200]
    else:
        # Fallback: write disassembly listing.
        try:
            end = idc.find_func_end(ea)
            lines = []
            cur = ea
            while cur < end and cur != idc.BADADDR:
                lines.append("%x: %s" % (cur, idc.GetDisasm(cur)))
                cur = idc.next_head(cur, end)
            text = "// HEXRAYS UNAVAILABLE: " + _hx_err + "\n" + "\n".join(lines)
            with open(fn_path, "w", encoding="utf-8") as f:
                f.write(text)
            entry["size"] = len(text)
            entry["fallback"] = "disasm"
        except Exception as e:
            failed += 1
            entry["error"] = str(e)[:200]

    summary.append(entry)

meta = {
    "tool": "ida_headless.py dump",
    "hexrays": HAVE_HEXRAYS,
    "dumped": len(summary),
    "skipped": skipped,
    "failed": failed,
    "functions": summary,
}
with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)

# Write a marker file so the CLI can detect success.
with open(os.path.join(out_dir, "_dump_done"), "w") as f:
    f.write("ok\n")

idc.qexit(0)
'''


# Metadata script — single JSON with functions, imports, strings, xrefs.
METADATA_SCRIPT = r'''
import os, json, traceback
import idaapi, idautils, idc, ida_nalt, ida_name

idaapi.auto_wait()

out_path = os.environ.get("IDA_META_OUT", "ida_meta.json")

functions = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea) or ""
    end = idc.find_func_end(ea)
    flags = idc.get_func_flags(ea) or 0
    functions.append({
        "name": name,
        "addr": "0x%x" % ea,
        "end": "0x%x" % (end if end != idc.BADADDR else ea),
        "size": (end - ea) if end != idc.BADADDR else 0,
        "is_thunk": bool(flags & idaapi.FUNC_THUNK),
        "is_lib": bool(flags & idaapi.FUNC_LIB),
    })

# Imports — walk every import module in the binary.
imports = []
def _imp_cb(ea, name, ord_):
    imports.append({"addr": "0x%x" % ea, "name": name or "", "ord": ord_})
    return True
try:
    n_mods = ida_nalt.get_import_module_qty()
    for i in range(n_mods):
        mod_name = ida_nalt.get_import_module_name(i) or ""
        mod_imports = []
        def _cb(ea, name, ord_, mod=mod_name):
            mod_imports.append({"addr": "0x%x" % ea, "name": name or "", "ord": ord_, "module": mod})
            return True
        ida_nalt.enum_import_names(i, _cb)
        imports.extend(mod_imports)
except Exception:
    pass

# Strings — only non-trivial ones to keep JSON small.
strings = []
try:
    for s in idautils.Strings():
        text = str(s)
        if len(text) >= 4:
            strings.append({"addr": "0x%x" % s.ea, "len": len(text), "value": text[:200]})
            if len(strings) >= 5000:
                break
except Exception:
    pass

# Build xref map keyed by the callee name so agents can locate callers cheaply.
xrefs_to = {}
interesting = {"ptrace", "alarm", "signal", "getauxval", "rand", "srand",
               "time", "clock_gettime", "gettimeofday", "fopen",
               "scanf", "gets", "read", "memcpy", "strcpy", "system",
               "puts", "printf", "strcmp", "strncmp"}
for f in functions:
    short = f["name"].split("@")[0].split(".")[-1]
    if short in interesting or any(k in f["name"] for k in interesting):
        refs = []
        try:
            ea_int = int(f["addr"], 16)
            for xref in idautils.CodeRefsTo(ea_int, 0):
                caller = idc.get_func_name(xref) or ""
                refs.append({"from": "0x%x" % xref, "func": caller})
        except Exception:
            pass
        if refs:
            xrefs_to[f["name"]] = refs

meta = {
    "tool": "ida_headless.py metadata",
    "binary": ida_nalt.get_root_filename() or "",
    "entry_point": "0x%x" % idaapi.inf_get_start_ea(),
    "arch": idaapi.get_inf_structure().procname if hasattr(idaapi, "get_inf_structure") else "",
    "function_count": len(functions),
    "functions": functions,
    "import_count": len(imports),
    "imports": imports,
    "string_count": len(strings),
    "strings": strings,
    "xrefs_to_interesting": xrefs_to,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)

idc.qexit(0)
'''


# Combined full script (dump + metadata in one IDA run).
# Strip the trailing idc.qexit(0) from DUMP_SCRIPT (we only want one at the end)
# and drop the second auto_wait since it's already been called.
def _build_full_script() -> str:
    dump_trimmed = DUMP_SCRIPT.rstrip()
    marker = "idc.qexit(0)"
    if dump_trimmed.endswith(marker):
        dump_trimmed = dump_trimmed[: -len(marker)].rstrip()
    meta_skipped = METADATA_SCRIPT.replace(
        "idaapi.auto_wait()", "# auto_wait already called"
    )
    return dump_trimmed + "\n\n" + meta_skipped

FULL_SCRIPT = _build_full_script()


# ---------------------------------------------------------------------------
# IDA invocation
# ---------------------------------------------------------------------------

def _run_ida(binary: Path, script_body: str, extra_env: dict,
             timeout: int = 300, keep_idb: bool = False) -> tuple[int, str, str]:
    """Invoke IDA headlessly with the given post-script.

    Returns (returncode, stdout, stderr). The IDB is created next to a copy of
    the binary in a temp dir so repeated runs don't clutter the challenge
    folder (unless keep_idb=True).
    """
    if not os.path.exists(IDA_PATH):
        return 127, "", f"IDA not found at {IDA_PATH}. Set IDA_PATH env var."

    with tempfile.TemporaryDirectory(prefix="ida_headless_") as tmp:
        tmp_dir = Path(tmp)
        # Work on a copy — IDA writes .i64 next to the binary.
        work_bin = tmp_dir / binary.name
        shutil.copy2(binary, work_bin)

        script_file = tmp_dir / "post.py"
        script_file.write_text(script_body, encoding="utf-8")

        env = os.environ.copy()
        env.update(extra_env)
        # Force IDA to avoid loading the MCP plugin autostart to keep this run
        # independent from the long-running MCP server instance.
        env["IDA_MCP_AUTOSTART"] = "0"

        cmd = [
            IDA_PATH,
            "-A",                     # auto-analysis, no UI dialogs
            "-S" + str(script_file),  # post-analysis script
            "-L" + str(tmp_dir / "ida.log"),
            str(work_bin),
        ]

        try:
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return 124, "", f"IDA timed out after {timeout}s"

        log_path = tmp_dir / "ida.log"
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

        if keep_idb:
            for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
                src = work_bin.with_suffix(work_bin.suffix + ext)
                if src.exists():
                    shutil.copy2(src, binary.parent / src.name)

        return proc.returncode, proc.stdout + "\n" + log_text, proc.stderr


# ---------------------------------------------------------------------------
# Subcommand: dump
# ---------------------------------------------------------------------------

def cmd_dump(args) -> int:
    binary = _abs(args.binary)
    if not binary.exists():
        print(f"[-] binary not found: {binary}", file=sys.stderr)
        return 2

    out_dir = _abs(args.out) if args.out else (binary.parent / "decompiled")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = {"IDA_DUMP_OUT": str(out_dir)}
    if args.filter:
        env["IDA_DUMP_FILTER"] = args.filter

    rc, stdout, stderr = _run_ida(binary, DUMP_SCRIPT, env, timeout=args.timeout)

    marker = out_dir / "_dump_done"
    summary_path = out_dir / "summary.json"

    if not marker.exists():
        print(f"[-] dump failed (rc={rc})", file=sys.stderr)
        if stderr:
            print(stderr[-1500:], file=sys.stderr)
        return 1
    marker.unlink(missing_ok=True)

    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        print(f"[+] dumped {summary['dumped']} functions → {out_dir}")
        print(f"    skipped={summary['skipped']} failed={summary['failed']} "
              f"hexrays={summary['hexrays']}")
        print(f"    summary: {summary_path}")
        print(f"    read a function: Read {out_dir}/<func_name>.c")
        print(f"    search pattern:  Grep <pattern> {out_dir}/")
    else:
        print(f"[+] dump completed → {out_dir}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: metadata
# ---------------------------------------------------------------------------

def cmd_metadata(args) -> int:
    binary = _abs(args.binary)
    if not binary.exists():
        print(f"[-] binary not found: {binary}", file=sys.stderr)
        return 2

    out_path = _abs(args.out) if args.out else (binary.parent / "ida_meta.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    env = {"IDA_META_OUT": str(out_path)}
    rc, stdout, stderr = _run_ida(binary, METADATA_SCRIPT, env, timeout=args.timeout)

    if not out_path.exists():
        print(f"[-] metadata dump failed (rc={rc})", file=sys.stderr)
        if stderr:
            print(stderr[-1500:], file=sys.stderr)
        return 1

    meta = json.loads(out_path.read_text(encoding="utf-8"))
    print(f"[+] metadata → {out_path}")
    print(f"    functions={meta['function_count']} "
          f"imports={meta['import_count']} strings={meta['string_count']}")
    if meta.get("xrefs_to_interesting"):
        hits = ", ".join(meta["xrefs_to_interesting"].keys())
        print(f"    interesting xrefs: {hits}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: patch
# ---------------------------------------------------------------------------

def cmd_patch(args) -> int:
    binary = _abs(args.binary)
    if not binary.exists():
        print(f"[-] binary not found: {binary}", file=sys.stderr)
        return 2

    user_script = _abs(args.script)
    if not user_script.exists():
        print(f"[-] IDAPython script not found: {user_script}", file=sys.stderr)
        return 2

    out_path = _abs(args.output) if args.output else binary.with_suffix(binary.suffix + ".patched")

    # Wrap the user script so it exits cleanly and ensures auto-analysis completion.
    wrapper = f'''
import os, idaapi, idc
idaapi.auto_wait()
try:
    exec(open({repr(str(user_script))}).read(), globals())
except SystemExit:
    pass
except Exception as e:
    import traceback
    print("[patch] user script error:", e)
    traceback.print_exc()

# Save patched bytes back to a new file.
out_path = {repr(str(out_path))}
try:
    import ida_loader
    ida_loader.save_database(out_path + ".i64", 0)
except Exception:
    pass

# Write a fresh binary reflecting idc.patch_byte edits.
try:
    import ida_bytes, ida_segment
    size = idaapi.inf_get_max_ea() - idaapi.inf_get_min_ea()
    start = idaapi.inf_get_min_ea()
    with open(out_path, "wb") as f:
        f.write(ida_bytes.get_bytes(start, size) or b"")
except Exception as e:
    print("[patch] could not write patched binary:", e)

idc.qexit(0)
'''
    rc, stdout, stderr = _run_ida(binary, wrapper, {}, timeout=args.timeout)
    if not out_path.exists():
        print(f"[-] patch run did not produce {out_path} (rc={rc})", file=sys.stderr)
        if stderr:
            print(stderr[-1500:], file=sys.stderr)
        return 1
    # chmod +x for convenience on Linux binaries.
    try:
        os.chmod(out_path, 0o755)
    except Exception:
        pass
    print(f"[+] patched binary → {out_path}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: full — dump + metadata in one IDA invocation
# ---------------------------------------------------------------------------

def cmd_full(args) -> int:
    binary = _abs(args.binary)
    if not binary.exists():
        print(f"[-] binary not found: {binary}", file=sys.stderr)
        return 2

    cdir = _abs(args.challenge_dir) if args.challenge_dir else binary.parent
    out_dir = cdir / "decompiled"
    out_dir.mkdir(parents=True, exist_ok=True)
    meta_out = cdir / "ida_meta.json"

    env = {
        "IDA_DUMP_OUT": str(out_dir),
        "IDA_META_OUT": str(meta_out),
    }
    if args.filter:
        env["IDA_DUMP_FILTER"] = args.filter

    rc, stdout, stderr = _run_ida(binary, FULL_SCRIPT, env, timeout=args.timeout)

    marker = out_dir / "_dump_done"
    if not marker.exists() and not meta_out.exists():
        print(f"[-] full analysis failed (rc={rc})", file=sys.stderr)
        if stderr:
            print(stderr[-1500:], file=sys.stderr)
        return 1
    marker.unlink(missing_ok=True)

    # Summarise both outputs.
    dumped = skipped = failed = 0
    summary_path = out_dir / "summary.json"
    if summary_path.exists():
        s = json.loads(summary_path.read_text(encoding="utf-8"))
        dumped = s.get("dumped", 0)
        skipped = s.get("skipped", 0)
        failed = s.get("failed", 0)

    fc = imp = sc = 0
    hits = []
    if meta_out.exists():
        m = json.loads(meta_out.read_text(encoding="utf-8"))
        fc = m.get("function_count", 0)
        imp = m.get("import_count", 0)
        sc = m.get("string_count", 0)
        hits = list(m.get("xrefs_to_interesting", {}).keys())

    print(f"[+] full analysis complete")
    print(f"    decompiled: {dumped} funcs (skipped={skipped} failed={failed}) → {out_dir}")
    print(f"    metadata:   {fc} funcs, {imp} imports, {sc} strings → {meta_out}")
    if hits:
        print(f"    interesting xrefs: {', '.join(hits)}")
    print(f"    next: Grep '<pattern>' {out_dir}/ | Read {out_dir}/<func>.c")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="IDA Pro headless decompiler + metadata")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("dump", help="Decompile all functions to <out>/*.c")
    s.add_argument("binary")
    s.add_argument("--out", default=None, help="Output directory (default: <binary>/../decompiled)")
    s.add_argument("--filter", default="", help="Comma-separated function name filter")
    s.add_argument("--timeout", type=int, default=300)

    s = sub.add_parser("metadata", help="Dump functions/imports/strings/xrefs → JSON")
    s.add_argument("binary")
    s.add_argument("--out", default=None, help="Output JSON path (default: <binary>/../ida_meta.json)")
    s.add_argument("--timeout", type=int, default=300)

    s = sub.add_parser("patch", help="Run an IDAPython script and save a patched binary")
    s.add_argument("binary")
    s.add_argument("--script", required=True, help="IDAPython script file")
    s.add_argument("-o", "--output", default=None, help="Output patched binary path")
    s.add_argument("--timeout", type=int, default=300)

    s = sub.add_parser("full", help="dump + metadata in one IDA run (recommended)")
    s.add_argument("binary")
    s.add_argument("--challenge-dir", default=None,
                   help="Challenge directory (decompiled/ and ida_meta.json go here)")
    s.add_argument("--filter", default="", help="Comma-separated function name filter")
    s.add_argument("--timeout", type=int, default=300)

    args = p.parse_args()
    dispatch = {"dump": cmd_dump, "metadata": cmd_metadata, "patch": cmd_patch, "full": cmd_full}
    sys.exit(dispatch[args.cmd](args))


if __name__ == "__main__":
    main()
