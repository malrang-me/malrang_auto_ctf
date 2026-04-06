#!/usr/bin/env python3
"""
Crypto Pre-screening — fast checks before spawning full solver agent.
Attempts to solve easy crypto (factordb, small e, dp/dq, phi known) automatically.

Usage:
  crypto_prescreen.py <challenge_dir> [--subtype rsa] [--params '{"e_value":3}']

Returns JSON: {"solved": true, "flag": "..."} or {"solved": false, "reason": "..."}
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent


def _long_to_bytes(n):
    """Convert int to bytes."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


def _extract_params_from_files(challenge_dir: Path) -> dict:
    """Extract n, e, ct from output files and source code."""
    params = {}
    # Read output.txt / data.txt for large integers
    for fname in ["output.txt", "enc.txt", "data.txt", "ciphertext.txt"]:
        fpath = challenge_dir / fname
        if not fpath.exists():
            continue
        try:
            text = fpath.read_text(errors="replace")[:10000]
            # Try common formats: n = ..., e = ..., ct = ...
            for key in ["n", "N", "e", "ct", "c", "ciphertext", "phi", "dp", "dq"]:
                pattern = rf'\b{key}\b\s*[=:]\s*(\d{{10,}})'
                m = re.search(pattern, text)
                if m:
                    params[key.lower()] = int(m.group(1))
        except OSError:
            pass

    # Also check solve.py for hardcoded values (from previous attempts)
    for fname in ["solve.py", "chall.py"]:
        fpath = challenge_dir / fname
        if not fpath.exists():
            # Check deploy/ subdirectory
            for f in challenge_dir.rglob(fname):
                fpath = f
                break
        if fpath.exists():
            try:
                text = fpath.read_text(errors="replace")[:10000]
                for key in ["n", "e", "ct", "c", "phi", "dp", "dq"]:
                    pattern = rf'\b{key}\b\s*=\s*(\d{{10,}})'
                    m = re.search(pattern, text)
                    if m and key not in params:
                        params[key.lower()] = int(m.group(1))
            except OSError:
                pass

    return params


def prescreen_rsa(params: dict) -> dict:
    """Try fast RSA attacks. Returns {"solved": bool, "flag": str, "method": str}."""
    n = params.get("n") or params.get("N")
    e = params.get("e")
    ct = params.get("ct") or params.get("c") or params.get("ciphertext")

    if not (n and e and ct):
        return {"solved": False, "reason": "Missing n, e, or ct"}

    # 1. Small e: integer eth root
    if e and e <= 17:
        try:
            import gmpy2
            m, is_exact = gmpy2.iroot(ct, e)
            if is_exact:
                flag = _long_to_bytes(int(m))
                if b'{' in flag or flag.isascii():
                    return {"solved": True, "flag": flag.decode(errors="replace"),
                            "method": "integer_eth_root"}
        except (ImportError, Exception):
            pass

    # 2. phi known: direct decrypt
    phi = params.get("phi") or params.get("totient")
    if phi:
        try:
            from math import gcd
            if gcd(e, phi) == 1:
                d = pow(e, -1, phi)
                m = pow(ct, d, n)
                flag = _long_to_bytes(m)
                if b'{' in flag or flag.isascii():
                    return {"solved": True, "flag": flag.decode(errors="replace"),
                            "method": "phi_known_decrypt"}
        except Exception:
            pass

    # 3. dp/dq known: factor n
    dp = params.get("dp")
    dq = params.get("dq")
    if dp:
        try:
            from math import gcd
            for k in range(1, e + 1 if e < 100 else 100):
                p_candidate = (e * dp - 1 + k) // k
                if p_candidate > 1 and n % p_candidate == 0:
                    p = p_candidate
                    q = n // p
                    phi_val = (p - 1) * (q - 1)
                    d = pow(e, -1, phi_val)
                    m = pow(ct, d, n)
                    flag = _long_to_bytes(m)
                    return {"solved": True, "flag": flag.decode(errors="replace"),
                            "method": "dp_recovery"}
        except Exception:
            pass

    # 4. Small n: try factordb via requests (if available)
    if n and n.bit_length() <= 512:
        try:
            import requests
            resp = requests.get(f"http://factordb.com/api?query={n}", timeout=10)
            data = resp.json()
            if data.get("status") == "FF":  # fully factored
                factors = data.get("factors", [])
                if len(factors) >= 2:
                    p = int(factors[0][0])
                    q = n // p
                    if p * q == n:
                        phi_val = (p - 1) * (q - 1)
                        d = pow(e, -1, phi_val)
                        m = pow(ct, d, n)
                        flag = _long_to_bytes(m)
                        return {"solved": True, "flag": flag.decode(errors="replace"),
                                "method": "factordb"}
        except Exception:
            pass

    # 5. Try sympy factorization for small n
    if n and n.bit_length() <= 256:
        try:
            from sympy import factorint
            factors = factorint(n, limit=10**7)
            if len(factors) >= 2:
                phi_val = 1
                for p, exp in factors.items():
                    phi_val *= (p - 1) * (p ** (exp - 1))
                d = pow(e, -1, phi_val)
                m = pow(ct, d, n)
                flag = _long_to_bytes(m)
                return {"solved": True, "flag": flag.decode(errors="replace"),
                        "method": "sympy_factor"}
        except Exception:
            pass

    return {"solved": False, "reason": "No fast RSA attack succeeded"}


def prescreen(challenge_dir: str, subtype: str = None, params: dict = None) -> dict:
    """Main pre-screening dispatcher."""
    cdir = Path(challenge_dir).resolve()

    if not params:
        params = _extract_params_from_files(cdir)

    if not subtype:
        # Try to detect from triage
        try:
            sys.path.insert(0, str(MACHINE_ROOT / "tools"))
            from triage import detect_crypto_subtype
            info = detect_crypto_subtype(cdir)
            subtype = info.get("subtype", "unknown")
            params.update(info.get("params", {}))
        except ImportError:
            subtype = "unknown"

    if subtype == "rsa":
        return prescreen_rsa(params)

    # Other subtypes don't have fast pre-screening (need Sage etc.)
    return {"solved": False, "reason": f"No prescreen for subtype: {subtype}"}


def main():
    p = argparse.ArgumentParser(description="Crypto Pre-screening")
    p.add_argument("challenge_dir", help="Path to challenge directory")
    p.add_argument("--subtype", default=None)
    p.add_argument("--params", default=None, help="JSON params")
    args = p.parse_args()

    params = json.loads(args.params) if args.params else None
    result = prescreen(args.challenge_dir, args.subtype, params)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
