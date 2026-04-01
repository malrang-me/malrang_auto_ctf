#!/usr/bin/env python3
"""Generate meta.yaml for all challenges that don't have one."""
import os
import re
from datetime import datetime
from pathlib import Path

CHALLENGES_DIR = Path(__file__).resolve().parent.parent / "challenges"

# Category detection heuristics
def detect_category(challenge_dir: Path) -> str:
    files = [f.name.lower() for f in challenge_dir.rglob("*") if f.is_file()]
    all_text = " ".join(files)

    # Check for exploit.py → pwn or web
    if "exploit.py" in files:
        # Check contents for pwntools vs requests
        ep = challenge_dir / "exploit.py"
        if ep.exists():
            code = ep.read_text(errors="ignore")
            if "pwntools" in code or "remote(" in code or "process(" in code:
                return "pwn"
            if "requests" in code or "curl" in code or "http" in code.lower():
                return "web"
        return "pwn"

    # Check memory/recon.md or discoveries.md for category hints
    for md_file in ["memory/recon.md", "memory/strategy.md", "memory/discoveries.md"]:
        fp = challenge_dir / md_file
        if fp.exists():
            content = fp.read_text(errors="ignore").lower()
            if any(kw in content for kw in ["rsa", "aes", "cipher", "encrypt", "lattice", "prng", "modular"]):
                return "crypto"
            if any(kw in content for kw in ["buffer overflow", "rop", "shellcode", "canary", "libc", "gadget"]):
                return "pwn"
            if any(kw in content for kw in ["ssti", "sqli", "xss", "ssrf", "endpoint", "route", "flask", "express"]):
                return "web"
            if any(kw in content for kw in ["disassembly", "assembly", "decompile", "crackme", "keygen", "reverse"]):
                return "reversing"
            if any(kw in content for kw in ["contract", "solidity", "ethereum", "web3", "blockchain"]):
                return "web3"
            if any(kw in content for kw in ["onnx", "model", "neural", "tensor", "machine learning"]):
                return "ai"

    # File extension heuristics
    if any(f.endswith((".sol",)) for f in files):
        return "web3"
    if any(f.endswith((".elf", ".bin")) for f in files) or "libc" in all_text:
        return "pwn"
    if any("docker" in f or "dockerfile" in f for f in files):
        return "web"
    if any(f.endswith((".sage",)) for f in files):
        return "crypto"
    if any(f.endswith((".onnx",)) for f in files):
        return "ai"

    # Check solve.py contents
    sp = challenge_dir / "solve.py"
    if sp.exists():
        code = sp.read_text(errors="ignore").lower()
        if "gmpy2" in code or "rsa" in code or "pow(" in code or "inverse" in code:
            return "crypto"
        if "z3" in code or "bitvec" in code or "angr" in code:
            return "reversing"

    return "misc"


def detect_status(challenge_dir: Path) -> str:
    """Detect if challenge was solved."""
    for f in challenge_dir.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".md", ".txt", ".sage"):
            try:
                content = f.read_text(errors="ignore")
                flags = re.findall(r"DH\{[^}]+\}", content)
                real_flags = [fl for fl in flags if fl not in (
                    "DH{flag}", "DH{testflag}", "DH{test_test}",
                    "DH{UPATCHED}", "DH{...}", "DH{" + "?" * 25 + "}"
                ) and "?" * 5 not in fl]
                if real_flags:
                    return "solved"
            except Exception:
                pass
    return "attempted"


def generate_meta(challenge_dir: Path):
    name = challenge_dir.name
    category = detect_category(challenge_dir)
    status = detect_status(challenge_dir)

    meta = f"""name: {name}
category: {category}
platform: dreamhack
remote_host: ""
remote_port: ""
status: {status}
created_at: {datetime.now().isoformat()}
"""
    meta_path = challenge_dir / "meta.yaml"
    meta_path.write_text(meta, encoding="utf-8")
    return category, status


def main():
    generated = 0
    skipped = 0
    for d in sorted(CHALLENGES_DIR.iterdir()):
        if not d.is_dir():
            continue
        meta = d / "meta.yaml"
        if meta.exists():
            print(f"  [skip] {d.name} (already has meta.yaml)")
            skipped += 1
            continue
        cat, status = generate_meta(d)
        print(f"  [gen]  {d.name}: {cat} / {status}")
        generated += 1

    print(f"\nDone: {generated} generated, {skipped} skipped")


if __name__ == "__main__":
    main()
