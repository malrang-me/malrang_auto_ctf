#!/usr/bin/env python3
"""
pwn_setup.py -- Pin challenge binary to provided libc and extract offsets.

The #1 source of "works locally, fails remotely" pwn bugs is libc-version
mismatch: the binary was linked against glibc A but the local WSL has glibc B,
so one_gadget / system / __free_hook offsets are silently wrong. The pipeline
test passes (both sides use the same wrong libc) but the remote payload
crashes.

This tool fixes that by:
  1. Detecting provided libc.so.6 (and ld-linux) in the challenge dir
  2. Reading both the provided libc version and the WSL system libc version
  3. patchelf-ing the binary so local execution loads the provided libc
  4. Running one_gadget on the *provided* libc (never the system one)
  5. Extracting common exploit symbols into libc_offsets.json

After running this, chain agents must read libc_offsets.json instead of
calling one_gadget themselves.

Usage:
  python tools/pwn_setup.py challenges/<name>
  python tools/pwn_setup.py challenges/<name> --binary chall
  python tools/pwn_setup.py challenges/<name> --no-patchelf  # offsets only
  python tools/pwn_setup.py check challenges/<name>          # status only

Requires WSL with: patchelf, one_gadget (gem), readelf, strings
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent

# Common symbols every chain agent needs
EXPLOIT_SYMBOLS = [
    "system",
    "execve",
    "__libc_system",
    "puts",
    "printf",
    "read",
    "write",
    "gets",
    "setbuf",
    "exit",
    "__libc_start_main",
    "__free_hook",
    "__malloc_hook",
    "_environ",
    "environ",
    "stdin",
    "stdout",
    "stderr",
]

# Strings to find inside libc
STRING_SEARCHES = ["/bin/sh", "/bin/bash", "sh\x00"]


def wsl(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command via WSL. Returns (rc, stdout, stderr)."""
    full = ["wsl", "--"] + cmd
    try:
        p = subprocess.run(
            full,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "wsl not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def to_wsl_path(p: Path) -> str:
    """Convert Windows path to WSL /mnt/c/... form."""
    s = str(p.resolve())
    if len(s) >= 2 and s[1] == ":":
        drive = s[0].lower()
        rest = s[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return s.replace("\\", "/")


def find_files(cdir: Path) -> dict:
    """Find binary, libc, ld in the challenge dir."""
    found = {"binary": None, "libc": None, "ld": None}

    # libc: libc.so.6, libc-2.31.so, libc6_*.so etc.
    for p in cdir.rglob("libc*.so*"):
        if p.is_file():
            found["libc"] = p
            break

    # ld: ld-linux-x86-64.so.2, ld-2.31.so etc.
    for p in cdir.rglob("ld-*.so*"):
        if p.is_file():
            found["ld"] = p
            break
    if not found["ld"]:
        for p in cdir.rglob("ld-linux*"):
            if p.is_file():
                found["ld"] = p
                break

    # binary: ELF that isn't libc/ld
    for p in cdir.iterdir():
        if not p.is_file():
            continue
        if p.suffix in (".py", ".md", ".json", ".yaml", ".yml", ".txt", ".so"):
            continue
        if "libc" in p.name.lower() or "ld-" in p.name.lower():
            continue
        # Quick ELF magic check
        try:
            with p.open("rb") as f:
                if f.read(4) == b"\x7fELF":
                    found["binary"] = p
                    break
        except OSError:
            continue

    return found


def libc_version(libc_path: Path | str) -> str | None:
    """Extract glibc version string from a libc file (via WSL strings)."""
    if isinstance(libc_path, Path):
        path = to_wsl_path(libc_path)
    else:
        path = libc_path
    rc, out, _ = wsl(["bash", "-c", f"strings {path} | grep -m1 'GNU C Library'"])
    if rc != 0 or not out:
        return None
    m = re.search(r"release version ([\d.]+)", out)
    if m:
        return m.group(1)
    m = re.search(r"glibc[- ]([\d.]+)", out)
    return m.group(1) if m else None


def system_libc_version() -> tuple[str | None, str | None]:
    """Return (path, version) of the WSL system libc."""
    rc, out, _ = wsl(["bash", "-c", "readlink -f /lib/x86_64-linux-gnu/libc.so.6"])
    if rc != 0:
        rc, out, _ = wsl(["bash", "-c", "ldconfig -p | grep -m1 'libc.so.6 (libc6,x86-64)' | awk '{print $NF}'"])
    sys_path = (out or "").strip() or None
    return sys_path, libc_version(sys_path) if sys_path else None


def run_one_gadget(libc_path: Path) -> list[dict]:
    """Run one_gadget on the provided libc, return list of {offset, constraints}."""
    wsl_libc = to_wsl_path(libc_path)
    rc, out, err = wsl(["bash", "-c", f"one_gadget --raw {wsl_libc} 2>/dev/null"])
    raw_offsets = []
    if rc == 0 and out.strip():
        for ln in out.splitlines():
            ln = ln.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", ln):
                raw_offsets.append(int(ln, 16))

    # Also get the human-readable form for constraints
    rc2, full, _ = wsl(["bash", "-c", f"one_gadget {wsl_libc} 2>/dev/null"])
    constraints_map = {}
    if rc2 == 0 and full:
        current_off = None
        current_lines = []
        for ln in full.splitlines():
            m = re.match(r"^(0x[0-9a-fA-F]+)\s", ln)
            if m:
                if current_off is not None:
                    constraints_map[current_off] = "\n".join(current_lines).strip()
                current_off = int(m.group(1), 16)
                current_lines = [ln]
            elif current_off is not None:
                current_lines.append(ln)
        if current_off is not None:
            constraints_map[current_off] = "\n".join(current_lines).strip()

    result = []
    for off in raw_offsets:
        result.append({"offset": off, "offset_hex": hex(off), "constraints": constraints_map.get(off, "")})
    return result


def extract_symbols(libc_path: Path) -> dict:
    """Extract common exploit symbol offsets via readelf."""
    wsl_libc = to_wsl_path(libc_path)
    rc, out, _ = wsl(["bash", "-c", f"readelf -Ws {wsl_libc}"])
    if rc != 0:
        return {}

    syms = {}
    for ln in out.splitlines():
        parts = ln.split()
        # readelf -Ws columns: Num Value Size Type Bind Vis Ndx Name
        if len(parts) < 8:
            continue
        try:
            value = int(parts[1], 16)
        except ValueError:
            continue
        name = parts[7].split("@")[0]  # strip @GLIBC_2.x
        if name in EXPLOIT_SYMBOLS and name not in syms:
            syms[name] = {"offset": value, "offset_hex": hex(value)}
    return syms


def find_strings_in_libc(libc_path: Path) -> dict:
    """Find offsets of /bin/sh etc. in libc."""
    wsl_libc = to_wsl_path(libc_path)
    found = {}
    for needle in STRING_SEARCHES:
        # Use python inside wsl for binary-safe search
        py = (
            f"import sys; "
            f"d=open('{wsl_libc}','rb').read(); "
            f"i=d.find({needle.encode()!r}); "
            f"print(hex(i) if i>=0 else '')"
        )
        rc, out, _ = wsl(["python3", "-c", py])
        out = out.strip()
        if rc == 0 and out:
            found[needle] = {"offset": int(out, 16), "offset_hex": out}
    return found


def patchelf_binary(binary: Path, libc: Path, ld: Path | None) -> tuple[bool, str]:
    """patchelf the binary to use the provided libc + ld. Creates <binary>.patched."""
    wsl_bin = to_wsl_path(binary)
    wsl_libc_dir = to_wsl_path(libc.parent)
    patched = binary.with_name(binary.name + ".patched")
    wsl_patched = to_wsl_path(patched)

    # Copy original to .patched
    rc, _, err = wsl(["bash", "-c", f"cp {wsl_bin} {wsl_patched}"])
    if rc != 0:
        return False, f"copy failed: {err}"

    cmds = [f"patchelf --set-rpath {wsl_libc_dir} {wsl_patched}"]
    if ld is not None:
        wsl_ld = to_wsl_path(ld)
        cmds.append(f"patchelf --set-interpreter {wsl_ld} {wsl_patched}")
    cmds.append(f"chmod +x {wsl_patched}")

    for c in cmds:
        rc, _, err = wsl(["bash", "-c", c])
        if rc != 0:
            return False, f"{c} -> {err}"
    return True, str(patched)


def setup(cdir: Path, do_patchelf: bool = True, binary_name: str | None = None) -> dict:
    """Run full pin-libc + extract-offsets workflow."""
    report = {
        "challenge_dir": str(cdir),
        "binary": None,
        "libc": None,
        "ld": None,
        "libc_version_provided": None,
        "libc_version_system": None,
        "libc_mismatch": False,
        "patched_binary": None,
        "one_gadget": [],
        "symbols": {},
        "strings": {},
        "warnings": [],
        "errors": [],
    }

    found = find_files(cdir)
    if binary_name:
        cand = cdir / binary_name
        if cand.exists():
            found["binary"] = cand

    if not found["binary"]:
        report["errors"].append("No ELF binary found in challenge directory")
        return report
    report["binary"] = str(found["binary"].relative_to(cdir))

    if not found["libc"]:
        report["warnings"].append(
            "No libc.so.6 provided in challenge dir. Cannot pin libc -- "
            "remote offsets WILL differ from local. Download via libc-database "
            "if you have a leak."
        )
        # Still try to read system libc version for the report
        sys_path, sys_ver = system_libc_version()
        report["libc_version_system"] = sys_ver
        return report

    report["libc"] = str(found["libc"].relative_to(cdir))
    if found["ld"]:
        report["ld"] = str(found["ld"].relative_to(cdir))

    # Version comparison
    provided_ver = libc_version(found["libc"])
    sys_path, sys_ver = system_libc_version()
    report["libc_version_provided"] = provided_ver
    report["libc_version_system"] = sys_ver
    if provided_ver and sys_ver and provided_ver != sys_ver:
        report["libc_mismatch"] = True
        report["warnings"].append(
            f"LIBC MISMATCH: provided={provided_ver} system={sys_ver}. "
            f"Local execution MUST use patched binary or LD_PRELOAD."
        )

    # patchelf
    if do_patchelf:
        ok, info = patchelf_binary(found["binary"], found["libc"], found["ld"])
        if ok:
            report["patched_binary"] = str(Path(info).relative_to(cdir))
        else:
            report["errors"].append(f"patchelf failed: {info}")

    # one_gadget
    gadgets = run_one_gadget(found["libc"])
    report["one_gadget"] = gadgets
    if not gadgets:
        report["warnings"].append("one_gadget produced no results (install: gem install one_gadget)")

    # symbols
    report["symbols"] = extract_symbols(found["libc"])
    if not report["symbols"]:
        report["warnings"].append("readelf produced no symbols (stripped libc?)")

    # strings
    report["strings"] = find_strings_in_libc(found["libc"])

    return report


def write_report(cdir: Path, report: dict) -> Path:
    out = cdir / "libc_offsets.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def cmd_setup(args):
    cdir = Path(args.challenge_dir).resolve()
    if not cdir.is_dir():
        print(f"[pwn_setup] ERROR: not a directory: {cdir}", file=sys.stderr)
        sys.exit(2)

    report = setup(cdir, do_patchelf=not args.no_patchelf, binary_name=args.binary)
    out_path = write_report(cdir, report)

    print(f"[pwn_setup] {out_path}")
    print(f"  binary:   {report['binary']}")
    print(f"  libc:     {report['libc']}  (provided={report['libc_version_provided']})")
    print(f"  ld:       {report['ld']}")
    print(f"  system libc: {report['libc_version_system']}")
    if report["libc_mismatch"]:
        print(f"  *** LIBC MISMATCH *** -- patched binary required")
    if report["patched_binary"]:
        print(f"  patched:  {report['patched_binary']}")
    print(f"  one_gadget: {len(report['one_gadget'])} gadgets")
    print(f"  symbols:    {len(report['symbols'])} (system={'system' in report['symbols']})")
    print(f"  strings:    {list(report['strings'].keys())}")
    for w in report["warnings"]:
        print(f"  WARN: {w}")
    for e in report["errors"]:
        print(f"  ERR:  {e}")

    sys.exit(0 if not report["errors"] else 1)


def cmd_check(args):
    """Just check libc version status without modifying anything."""
    cdir = Path(args.challenge_dir).resolve()
    found = find_files(cdir)
    if not found["libc"]:
        print(f"[check] no libc provided -- system libc will be used (mismatch risk HIGH)")
        sys.exit(0)
    pv = libc_version(found["libc"])
    _, sv = system_libc_version()
    print(f"[check] provided={pv} system={sv}")
    if pv and sv and pv != sv:
        print(f"[check] MISMATCH -- run: python tools/pwn_setup.py {args.challenge_dir}")
        sys.exit(1)
    print(f"[check] OK (versions match or one is unknown)")
    sys.exit(0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    p_setup = sub.add_parser("setup", help="(default) pin libc + extract offsets")
    p_setup.add_argument("challenge_dir")
    p_setup.add_argument("--binary", help="explicit binary name (otherwise auto-detected)")
    p_setup.add_argument("--no-patchelf", action="store_true", help="extract offsets only, no patching")
    p_setup.set_defaults(func=cmd_setup)

    p_check = sub.add_parser("check", help="report mismatch status without changes")
    p_check.add_argument("challenge_dir")
    p_check.set_defaults(func=cmd_check)

    # Default to "setup" if first arg is a directory
    if len(sys.argv) >= 2 and sys.argv[1] not in ("setup", "check", "-h", "--help"):
        sys.argv.insert(1, "setup")

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
