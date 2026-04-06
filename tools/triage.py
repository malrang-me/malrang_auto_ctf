#!/usr/bin/env python3
"""
malrang_auto_ctf — Challenge Triage Engine
======================================
Automatically classifies CTF challenges and retrieves relevant knowledge.

Usage:
  triage.py <challenge_dir> [--category CAT]  # full triage → JSON
  triage.py <challenge_dir> --context          # output knowledge context block only

Output: JSON with category, difficulty, pipeline mode, and knowledge context.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MACHINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MACHINE_ROOT / "tools"))

# ---------------------------------------------------------------------------
# Crypto Sub-type Detection
# ---------------------------------------------------------------------------

# Regex patterns for crypto sub-type detection (applied to source files)
CRYPTO_SUBTYPE_SIGNALS = {
    "rsa": [
        (r'getPrime|generate_prime|nextprime', "getPrime"),
        (r'pow\s*\([^,]+,\s*[eE]\s*,\s*[nN]\s*\)', "pow(m,e,n)"),
        (r'bytes_to_long|long_to_bytes|number\.', "bytes_to_long"),
        (r'inverse\s*\([^,]*[eE][^,]*,?\s*phi', "inverse(e,phi)"),
        (r'\bdp\b.*=|d_p\s*=', "dp_leaked"),
        (r'\bdq\b.*=|d_q\s*=', "dq_leaked"),
        (r'\bphi\b\s*=|\btotient\b', "phi_value"),
        (r'RSA|rsa_', "RSA_explicit"),
        (r'multi.*prime|CRT.*decrypt', "multi_prime"),
    ],
    "ecc": [
        (r'EllipticCurve|elliptic_curve|EC\(', "EllipticCurve"),
        (r'discrete_log|ECDLP|ecdlp', "discrete_log"),
        (r'curve\s*\.\s*order|order\s*\(\s*\)', "curve_order"),
        (r'generator|base_point|G\s*=', "generator"),
        (r'scalar_mult|multiply|point_mul', "scalar_mult"),
        (r'weil_pairing|tate_pairing', "pairing"),
        (r'ECDSA|ecdsa|signature', "ECDSA"),
        (r'nonce|k\s*=.*random', "nonce_usage"),
    ],
    "lattice": [
        (r'\.LLL\(\)|lll_reduction|BKZ|bkz', "LLL_BKZ"),
        (r'small_roots|coppersmith', "small_roots"),
        (r'CVP|SVP|closest_vector', "CVP_SVP"),
        (r'knapsack|subset.?sum', "knapsack"),
        (r'Zmod\(|PolynomialRing|poly.*ring', "polynomial_ring"),
        (r'lattice|Matrix\s*\(\s*ZZ', "lattice_explicit"),
        (r'HNP|hidden.?number', "HNP"),
    ],
    "symmetric": [
        (r'AES\s*[\.(]|aes[_.]', "AES"),
        (r'DES\s*[\.(]|des[_.]|TripleDES', "DES"),
        (r'\bXOR\b|xor\s*\(|strxor', "XOR"),
        (r'\bECB\b|MODE_ECB|ecb', "ECB"),
        (r'\bCBC\b|MODE_CBC|cbc', "CBC"),
        (r'\bCTR\b|MODE_CTR|ctr', "CTR"),
        (r'\bGCM\b|MODE_GCM|gcm', "GCM"),
        (r'pad\s*\(|unpad\s*\(|PKCS7|pkcs7', "padding"),
        (r'nonce.*reuse|reuse.*nonce', "nonce_reuse"),
    ],
    "hash": [
        (r'sha256|sha1|sha512|SHA', "SHA"),
        (r'\bmd5\b|MD5', "MD5"),
        (r'HMAC|hmac', "HMAC"),
        (r'hashlib|hash\s*\(', "hashlib"),
        (r'length.?ext|HashPump', "length_extension"),
        (r'collision|birthday', "collision"),
        (r'\bcrc\b|CRC32|crc32', "CRC"),
    ],
    "prng": [
        (r'random\.\w+|Random\(\)', "random_module"),
        (r'MT19937|mersenne|mt_', "MT19937"),
        (r'LFSR|lfsr|linear.?feedback', "LFSR"),
        (r'LCG|lcg|linear.?congruential', "LCG"),
        (r'seed\s*\(|\.seed\b', "seed"),
        (r'getrandbits|randint|randbelow', "getrandbits"),
        (r'Dual_EC|dual.?ec', "Dual_EC"),
    ],
    "number_theory": [
        (r'discrete_log(?!.*curve)|dlog\b', "discrete_log"),
        (r'Pohlig.?Hellman|pohlig', "Pohlig_Hellman"),
        (r'\bCRT\b|chinese_remainder', "CRT"),
        (r'primitive_root|generator.*group', "primitive_root"),
        (r'quadratic.?residue|legendre|jacobi', "quadratic_residue"),
    ],
}

# RSA attack rules: (condition_func, attack_id, priority)
RSA_ATTACK_RULES = [
    (lambda p: p.get("dp_leaked") or p.get("dq_leaked"), "dp_dq_recovery", 1),
    (lambda p: p.get("phi_leaked"), "factor_from_phi", 1),
    (lambda p: p.get("multi_n"), "common_factor_gcd", 1),
    (lambda p: p.get("e_value") and p["e_value"] <= 17, "coppersmith_stereotyped", 1),
    (lambda p: p.get("e_value") and p["e_value"] <= 17 and p.get("multi_ct"), "hastad_broadcast", 1),
    (lambda p: p.get("e_value") and p["e_value"] > 2**20, "wiener", 2),
    (lambda p: p.get("n_bits") and p["n_bits"] <= 512, "factordb_or_yafu", 2),
    (lambda p: p.get("multi_prime"), "multi_prime_crt", 2),
    (lambda p: True, "rsactftool_all", 5),
]

ECC_ATTACK_RULES = [
    (lambda p: p.get("anomalous"), "smart_attack", 1),
    (lambda p: p.get("supersingular"), "mov_attack", 1),
    (lambda p: p.get("smooth_order"), "pohlig_hellman", 2),
    (lambda p: p.get("no_validation"), "invalid_curve", 2),
    (lambda p: p.get("singular"), "singular_curve", 1),
    (lambda p: p.get("nonce_bias"), "hnp_lattice", 2),
]

SUBTYPE_TEMPLATE_MAP = {
    "rsa": "crypto_rsa.py",
    "ecc": "crypto_ecc.sage",
    "lattice": "crypto_lattice.sage",
    "symmetric": "crypto_oracle.py",
    "hash": None,
    "prng": "crypto_prng.py",
    "number_theory": None,
}


def detect_crypto_subtype(challenge_dir: Path) -> dict:
    """Analyze crypto source files to detect sub-type and extract parameters.

    Returns dict with: subtype, signals, params, suggested_attacks, suggested_template
    """
    result = {
        "subtype": "unknown",
        "signals": [],
        "params": {},
        "suggested_attacks": [],
        "suggested_template": None,
    }

    # Collect source text from crypto-relevant files (recursive search in deploy/ etc.)
    source_text = ""
    output_text = ""
    crypto_source_names = {
        "chall.py", "encrypt.py", "cipher.py", "rsa.py", "aes.py",
        "server.py", "challenge.py", "prob.py", "task.py", "gen.py",
        "main.py", "chal.py", "secret.py", "keygen.py",
    }
    output_names = {"output.txt", "enc.txt", "encrypted.txt", "ciphertext.txt", "data.txt"}

    for f in challenge_dir.rglob("*"):
        if not f.is_file() or ".git" in f.parts:
            continue
        fname_lower = f.name.lower()
        try:
            if f.name in crypto_source_names or f.suffix == ".py":
                source_text += f.read_text(errors="replace")[:8000] + "\n"
            elif f.suffix == ".sage":
                source_text += f.read_text(errors="replace")[:4000] + "\n"
            elif f.name in output_names:
                output_text += f.read_text(errors="replace")[:4000] + "\n"
        except OSError:
            pass
        # Cap total text to prevent excessive scanning
        if len(source_text) > 30000:
            break

    if not source_text and not output_text:
        return result

    combined = source_text + "\n" + output_text

    # Score each subtype by matching signals
    subtype_scores = {}
    matched_signals = {}
    for subtype, patterns in CRYPTO_SUBTYPE_SIGNALS.items():
        score = 0
        signals = []
        for regex, signal_name in patterns:
            if re.search(regex, combined, re.IGNORECASE):
                score += 1
                signals.append(signal_name)
        if score > 0:
            subtype_scores[subtype] = score
            matched_signals[subtype] = signals

    if not subtype_scores:
        return result

    # Pick highest scoring subtype
    best_subtype = max(subtype_scores, key=subtype_scores.get)
    result["subtype"] = best_subtype
    result["signals"] = matched_signals[best_subtype]
    result["suggested_template"] = SUBTYPE_TEMPLATE_MAP.get(best_subtype)

    # Extract parameters based on subtype
    params = {}
    if best_subtype == "rsa":
        params = _extract_rsa_params(source_text, output_text)
    elif best_subtype == "ecc":
        params = _extract_ecc_params(source_text, output_text)
    elif best_subtype == "prng":
        params = _extract_prng_params(source_text)
    elif best_subtype == "symmetric":
        params = _extract_symmetric_params(source_text)
    result["params"] = params

    # Suggest attacks based on subtype + params
    result["suggested_attacks"] = _suggest_attacks(best_subtype, params)

    # If multiple subtypes detected with similar scores, note them
    if len(subtype_scores) > 1:
        sorted_types = sorted(subtype_scores.items(), key=lambda x: -x[1])
        if len(sorted_types) >= 2 and sorted_types[1][1] >= sorted_types[0][1] - 1:
            result["secondary_subtype"] = sorted_types[1][0]

    return result


def _extract_rsa_params(source: str, output: str) -> dict:
    """Extract RSA parameters from source code and output files."""
    params = {}

    # Detect e value
    e_match = re.search(r'\be\s*=\s*(\d+)', source)
    if e_match:
        params["e_value"] = int(e_match.group(1))

    # Detect n bit length
    n_match = re.search(r'(\d{4,})\s*(?:#.*n\b|#.*modulus)', source, re.IGNORECASE)
    if not n_match:
        # Try getPrime bit size
        bits_match = re.search(r'getPrime\s*\(\s*(\d+)\s*\)', source)
        if bits_match:
            params["prime_bits"] = int(bits_match.group(1))
            params["n_bits"] = int(bits_match.group(1)) * 2

    # Check for dp/dq leak
    if re.search(r'\bdp\b\s*=|\bd_p\b\s*=', source):
        params["dp_leaked"] = True
    if re.search(r'\bdq\b\s*=|\bd_q\b\s*=', source):
        params["dq_leaked"] = True

    # Check for phi leak
    if re.search(r'\bphi\b\s*=|\btotient\b\s*=', source):
        params["phi_leaked"] = True

    # Check for multiple n values (batch GCD)
    n_count = len(re.findall(r'\bn\d*\s*=\s*\d{20,}', source + output))
    if n_count > 1:
        params["multi_n"] = True

    # Check for multiple ciphertexts
    ct_count = len(re.findall(r'\b(?:ct|c|ciphertext)\d*\s*=\s*\d{20,}', source + output))
    if ct_count > 1:
        params["multi_ct"] = True

    # Check for multi-prime
    if re.search(r'multi.*prime|primes\s*=\s*\[', source, re.IGNORECASE):
        params["multi_prime"] = True

    # Detect n from output files (bit length)
    if output:
        big_nums = re.findall(r'(?:n|N)\s*[=:]\s*(\d{50,})', output)
        if big_nums:
            params["n_bits"] = len(big_nums[0]) * 3  # rough log2 estimate

    return params


def _extract_ecc_params(source: str, output: str) -> dict:
    """Extract ECC parameters."""
    params = {}

    # Detect curve definition
    if re.search(r'EllipticCurve\s*\(\s*GF\s*\(', source):
        params["sage_curve"] = True

    # Check for anomalous hint
    if re.search(r'order\s*==\s*p|anomalous|#E\s*=\s*p', source, re.IGNORECASE):
        params["anomalous"] = True

    # Check for nonce bias (ECDSA)
    if re.search(r'ECDSA|ecdsa|sign\s*\(', source, re.IGNORECASE):
        params["ecdsa"] = True
        if re.search(r'nonce.*(?:partial|bias|leak|msb|lsb)', source, re.IGNORECASE):
            params["nonce_bias"] = True

    # Check for no point validation
    if re.search(r'(?:no|skip|without).*valid', source, re.IGNORECASE):
        params["no_validation"] = True

    return params


def _extract_prng_params(source: str) -> dict:
    """Extract PRNG parameters."""
    params = {}

    if re.search(r'MT19937|mersenne', source, re.IGNORECASE):
        params["prng_type"] = "mt19937"
        # Count outputs
        output_calls = len(re.findall(r'getrandbits|randint|random\(\)', source))
        params["output_count_approx"] = output_calls

    elif re.search(r'LCG|linear.?congruential', source, re.IGNORECASE):
        params["prng_type"] = "lcg"
        # Try to extract modulus
        m_match = re.search(r'(?:modulus|m)\s*=\s*(\d+)', source)
        if m_match:
            params["lcg_modulus"] = int(m_match.group(1))

    elif re.search(r'LFSR|linear.?feedback', source, re.IGNORECASE):
        params["prng_type"] = "lfsr"

    return params


def _extract_symmetric_params(source: str) -> dict:
    """Extract symmetric crypto parameters."""
    params = {}

    # Detect mode
    for mode in ["ECB", "CBC", "CTR", "GCM", "OFB", "CFB"]:
        if re.search(rf'\b{mode}\b|MODE_{mode}', source, re.IGNORECASE):
            params["mode"] = mode.upper()
            break

    # Detect block size
    bs_match = re.search(r'block.?size\s*=\s*(\d+)', source, re.IGNORECASE)
    if bs_match:
        params["block_size"] = int(bs_match.group(1))

    # Detect oracle pattern
    if re.search(r'(recv|input|query).*decrypt|decrypt.*(send|print|output)', source, re.IGNORECASE):
        params["has_oracle"] = True

    # Detect nonce reuse
    if re.search(r'nonce.*reuse|same.*nonce|fixed.*nonce', source, re.IGNORECASE):
        params["nonce_reuse"] = True

    return params


def _suggest_attacks(subtype: str, params: dict) -> list:
    """Suggest attacks based on subtype and extracted parameters."""
    attacks = []

    if subtype == "rsa":
        for condition, attack_id, priority in RSA_ATTACK_RULES:
            try:
                if condition(params):
                    attacks.append({"id": attack_id, "priority": priority})
            except Exception:
                pass

    elif subtype == "ecc":
        for condition, attack_id, priority in ECC_ATTACK_RULES:
            try:
                if condition(params):
                    attacks.append({"id": attack_id, "priority": priority})
            except Exception:
                pass

    elif subtype == "lattice":
        attacks.append({"id": "coppersmith_direct", "priority": 2})
        attacks.append({"id": "lll_custom", "priority": 3})

    elif subtype == "symmetric":
        if params.get("has_oracle"):
            if params.get("mode") == "CBC":
                attacks.append({"id": "padding_oracle", "priority": 1})
            else:
                attacks.append({"id": "oracle_generic", "priority": 2})
        if params.get("nonce_reuse"):
            attacks.append({"id": "nonce_reuse_xor", "priority": 1})
        if params.get("mode") == "ECB":
            attacks.append({"id": "ecb_oracle", "priority": 1})

    elif subtype == "prng":
        pt = params.get("prng_type", "")
        if pt == "mt19937":
            attacks.append({"id": "mt_clone", "priority": 1})
        elif pt == "lcg":
            attacks.append({"id": "lcg_crack", "priority": 1})
        elif pt == "lfsr":
            attacks.append({"id": "lfsr_bm", "priority": 1})

    elif subtype == "hash":
        attacks.append({"id": "length_extension", "priority": 2})
        attacks.append({"id": "collision", "priority": 3})

    # Sort by priority
    attacks.sort(key=lambda a: a["priority"])
    return attacks


# ---------------------------------------------------------------------------
# Category Detection
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS = {".elf", ".exe", ".out", ".bin", ".so", ".dll", ".dylib"}
WEB_FILES = {"docker-compose.yml", "docker-compose.yaml", "Dockerfile",
             "app.py", "server.js", "index.js", "index.php", "main.go",
             "pom.xml", "build.gradle"}
CRYPTO_FILES = {"encrypt.py", "cipher.py", "rsa.py", "aes.py", "chall.py",
                "output.txt", "enc.txt", "encrypted.txt", "ciphertext.txt"}
FORENSICS_EXTENSIONS = {".pcap", ".pcapng", ".mem", ".raw", ".img", ".E01",
                        ".vmdk", ".ad1", ".dmp"}
WEB3_EXTENSIONS = {".sol", ".abi"}
WEB3_FILES = {"foundry.toml", "hardhat.config.js", "hardhat.config.ts",
              "truffle-config.js", "brownie-config.yaml"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".wav"}


def detect_category(challenge_dir: Path, hint: str = None) -> str:
    """Detect challenge category from files. Returns category string."""
    if hint and hint in ("pwn", "rev", "web", "crypto", "forensics", "web3", "misc"):
        return hint

    files = []
    for f in challenge_dir.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            files.append(f)

    names = {f.name for f in files}
    suffixes = {f.suffix.lower() for f in files}
    rel_names = {f.name.lower() for f in files}

    # Web3 — check first (most specific)
    if suffixes & WEB3_EXTENSIONS or names & WEB3_FILES:
        return "web3"

    # Web — docker-compose or web framework files
    if names & WEB_FILES:
        return "web"

    # Forensics — pcap, memory dumps, images with no binary
    if suffixes & FORENSICS_EXTENSIONS:
        return "forensics"

    # Check for ELF/PE binaries
    has_binary = False
    binary_path = None
    for f in files:
        if f.suffix.lower() in BINARY_EXTENSIONS:
            has_binary = True
            binary_path = f
            break
        # Check ELF magic for extensionless files
        if not f.suffix and f.stat().st_size > 4:
            try:
                with open(f, "rb") as fh:
                    magic = fh.read(4)
                if magic == b"\x7fELF" or magic[:2] == b"MZ":
                    has_binary = True
                    binary_path = f
                    break
            except (OSError, PermissionError):
                pass

    # Crypto — python files with crypto-like names, no binary
    if not has_binary and (names & CRYPTO_FILES or
            any(n.endswith(".sage") for n in rel_names)):
        return "crypto"
    # Also crypto if output.txt + *.py but no binary
    if not has_binary and "output.txt" in names and any(
            f.suffix == ".py" for f in files):
        return "crypto"

    # Image stego → forensics
    if suffixes & IMAGE_EXTENSIONS and not has_binary:
        return "forensics"

    # Binary present — pwn vs rev
    if has_binary and binary_path:
        # Check for network functions → pwn
        try:
            strings_out = subprocess.run(
                ["strings", str(binary_path)],
                capture_output=True, text=True, timeout=10
            ).stdout.lower()
            network_hints = ["socket", "bind", "listen", "accept", "recv",
                             "send", "connect", "htons", "inet"]
            vuln_hints = ["gets", "strcpy", "sprintf", "system", "execve",
                          "/bin/sh", "flag"]
            rev_hints = ["correct", "wrong", "invalid", "enter the",
                         "input:", "password:", "key:"]

            net_score = sum(1 for h in network_hints if h in strings_out)
            vuln_score = sum(1 for h in vuln_hints if h in strings_out)
            rev_score = sum(1 for h in rev_hints if h in strings_out)

            if net_score >= 2 or vuln_score >= 2:
                return "pwn"
            if rev_score >= 2:
                return "rev"
            # Default binary → rev (more common in CTF)
            return "rev"
        except Exception:
            return "rev"

    # Fallback
    return "misc"


# ---------------------------------------------------------------------------
# Difficulty Estimation
# ---------------------------------------------------------------------------

def estimate_difficulty(challenge_dir: Path, category: str,
                        similar_count: int = 0) -> str:
    """Estimate difficulty: easy / medium / hard.
    Returns heuristic estimate + raw signals for LLM override."""
    score = 0
    signals = []

    # Category baseline
    cat_base = {"forensics": 0, "misc": 0, "crypto": 1, "web": 1,
                "rev": 2, "pwn": 2, "web3": 3}
    score += cat_base.get(category, 2)

    # Similar solved challenges → easier
    if similar_count >= 2:
        score -= 2
        signals.append(f"similar_solved: {similar_count} (경험 있음)")
    elif similar_count >= 1:
        score -= 1
        signals.append(f"similar_solved: {similar_count}")

    # File complexity
    files = list(challenge_dir.rglob("*"))
    file_count = sum(1 for f in files if f.is_file())
    if file_count > 15:
        score += 1
    signals.append(f"files: {file_count}")

    # Docker multi-container
    compose = challenge_dir / "docker-compose.yml"
    if not compose.exists():
        compose = challenge_dir / "docker-compose.yaml"
    if compose.exists():
        try:
            content = compose.read_text()
            services = content.count("image:") + content.count("build:")
            signals.append(f"docker_services: {services}")
            if services > 2:
                score += 1
        except OSError:
            pass

    # Binary protections (pwn/rev)
    checksec_info = ""
    if category in ("pwn", "rev"):
        for f in files:
            if f.is_file() and not f.suffix:
                try:
                    with open(f, "rb") as fh:
                        magic = fh.read(4)
                    if magic == b"\x7fELF" or magic[:2] == b"MZ":
                        result = subprocess.run(
                            ["checksec", "--file=" + str(f), "--output=json"],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            data = json.loads(result.stdout)
                            props = {}
                            if isinstance(data, dict):
                                for v in data.values():
                                    if isinstance(v, dict):
                                        props = v
                                        break
                            pie = "pie" in str(props).lower()
                            canary = "canary" in str(props).lower() and "no" not in str(props.get("canary", "")).lower()
                            if pie and canary:
                                score += 1
                            checksec_info = str(props)[:200]
                            signals.append(f"checksec: {checksec_info}")
                        # Binary size
                        fsize = f.stat().st_size
                        signals.append(f"binary_size: {fsize} bytes")
                        break
                except Exception:
                    pass

    # Custom libc → harder
    if any(f.name.startswith("libc") for f in files if f.is_file()):
        score += 1
        signals.append("custom_libc: yes")

    # Source code complexity (line count of main source files)
    for src_name in ("chall.py", "encrypt.py", "app.py", "server.js", "main.go",
                     "index.php", "chall.c", "chall.cpp"):
        src = challenge_dir / src_name
        if src.exists():
            try:
                lines = len(src.read_text(errors="replace").splitlines())
                signals.append(f"source: {src_name} ({lines} lines)")
                if lines > 200:
                    score += 1
            except OSError:
                pass

    # Platform difficulty (from meta.yaml)
    meta = challenge_dir / "meta.yaml"
    if meta.exists():
        try:
            meta_text = meta.read_text(errors="replace").lower()
            for level_kw in ["level 1", "level 2", "level 3", "level 4", "level 5", "level 6"]:
                if level_kw in meta_text:
                    signals.append(f"platform_level: {level_kw}")
                    lvl = int(level_kw.split()[-1])
                    if lvl >= 5:
                        score += 2
                    elif lvl >= 3:
                        score += 1
                    break
        except OSError:
            pass

    heuristic = "easy" if score <= 1 else ("medium" if score <= 3 else "hard")
    signals.append(f"heuristic_score: {score} → {heuristic}")

    return heuristic, signals


def format_difficulty_signals(heuristic: str, signals: list) -> str:
    """Format signals for LLM to make final difficulty decision."""
    return (
        f"[DIFFICULTY SIGNALS — LLM이 최종 판단할 것]\n"
        f"heuristic: {heuristic}\n"
        + "\n".join(f"  - {s}" for s in signals)
        + "\n"
        f"오케스트레이터가 위 신호를 보고 easy/medium/hard 최종 결정.\n"
        f"heuristic과 다르게 판단해도 됨 (예: platform level 5인데 heuristic=medium이면 hard로 올려야)."
    )


# ---------------------------------------------------------------------------
# Knowledge Retrieval
# ---------------------------------------------------------------------------

def extract_relevant_category_sections(category: str, challenge_dir: Path) -> str:
    """Extract only relevant sections from category guide based on challenge signals.
    Instead of loading full 100+ line category file, returns ~20-30 relevant lines."""
    cat_file = MACHINE_ROOT / "categories" / f"{category}.md"
    if not cat_file.exists():
        return ""

    content = cat_file.read_text(encoding="utf-8", errors="replace")

    # Detect sub-type signals from challenge files
    signals = set()
    for desc_name in ("challenge.md", "README.md", "description.md", "meta.yaml",
                      "output.txt", "chall.py", "encrypt.py"):
        desc_path = challenge_dir / desc_name
        if desc_path.exists():
            try:
                text = desc_path.read_text(errors="replace")[:2000].lower()
                # Crypto sub-types
                if category == "crypto":
                    for kw, sig in [("rsa", "RSA"), ("aes", "AES"), ("ecc", "Elliptic"),
                                    ("elliptic", "Elliptic"), ("lattice", "Lattice"),
                                    ("lll", "Lattice"), ("prng", "PRNG"), ("mt19937", "PRNG"),
                                    ("lfsr", "PRNG"), ("lcg", "PRNG"), ("hash", "Hash"),
                                    ("sha", "Hash"), ("xor", "PRNG"), ("discrete_log", "Number Theory"),
                                    ("dlog", "Number Theory"), ("coppersmith", "Lattice")]:
                        if kw in text:
                            signals.add(sig)
                # Pwn sub-types
                elif category == "pwn":
                    for kw, sig in [("format", "Format String"), ("heap", "Heap"),
                                    ("uaf", "Heap"), ("tcache", "Heap"), ("stack", "Stack"),
                                    ("overflow", "Stack"), ("got", "GOT"), ("rop", "GOT")]:
                        if kw in text:
                            signals.add(sig)
                # Web sub-types
                elif category == "web":
                    for kw, sig in [("sql", "Injection"), ("ssti", "Injection"),
                                    ("jwt", "Auth"), ("ssrf", "File Ops"), ("lfi", "File Ops"),
                                    ("upload", "File Ops"), ("xss", "Client-Side"),
                                    ("pickle", "Deserialization"), ("unserialize", "Deserialization")]:
                        if kw in text:
                            signals.add(sig)
            except OSError:
                pass

    # If no signals detected, return essential sections only (First Steps + Pitfalls)
    if not signals:
        sections = []
        in_section = False
        for line in content.split("\n"):
            if line.startswith("## First Steps") or line.startswith("## Mandatory First Steps") or line.startswith("## Pitfalls"):
                in_section = True
                sections.append(line)
            elif line.startswith("## ") and in_section:
                in_section = False
            elif in_section:
                sections.append(line)
        return "\n".join(sections) if sections else content[:500]

    # Extract matching sections
    result_lines = []
    current_section = ""
    in_relevant = False

    for line in content.split("\n"):
        if line.startswith("### "):
            section_name = line[4:].strip()
            in_relevant = any(sig in section_name for sig in signals)
            if in_relevant:
                result_lines.append(line)
        elif line.startswith("## "):
            section_name = line[3:].strip()
            # Always include First Steps, Pitfalls, Tool sections
            in_relevant = any(k in section_name for k in
                            ["First Steps", "Mandatory First", "Pitfalls", "MCP Tools",
                             "Tools", "Chain Priority", "Primitive", "Framework Priority",
                             "Token-Efficient"])
            if in_relevant:
                result_lines.append(line)
            current_section = section_name
        elif in_relevant:
            result_lines.append(line)

    # If we got useful sections, return them; otherwise return compact version
    if len(result_lines) > 5:
        return f"[Category: {category} — filtered for: {', '.join(signals)}]\n" + "\n".join(result_lines)
    return content[:800]


def search_speedrun_memory(category: str, challenge_dir: Path, max_entries: int = 3) -> str:
    """Search SPEEDRUN_MEMORY via FTS5 index (fast) with markdown fallback.
    Returns ONLY matching entries, not the whole 67KB file."""

    # Try FTS5 index first (token-efficient: no full file parse)
    try:
        from speedrun_db import search, format_results, ensure_fresh
        ensure_fresh()  # auto-rebuild if MD is newer than DB
        # Build query from category + challenge keywords
        keywords = [category, challenge_dir.name.lower()]
        for desc_name in ("challenge.md", "README.md", "description.md", "meta.yaml"):
            desc_path = challenge_dir / desc_name
            if desc_path.exists():
                try:
                    text = desc_path.read_text(errors="replace")[:1000].lower()
                    kw_map = {
                        "crypto": ["rsa", "aes", "ecc", "lattice", "prng", "hash", "coppersmith"],
                        "rev": ["crackme", "xor", "vm", "packed", "angr", "z3", "maze"],
                        "pwn": ["overflow", "format", "heap", "uaf", "rop", "canary", "libc"],
                        "web": ["sqli", "ssti", "xss", "ssrf", "jwt", "flask", "php"],
                    }
                    for kw in kw_map.get(category, []):
                        if kw in text:
                            keywords.append(kw)
                except OSError:
                    pass
                break

        query = " ".join(keywords[:8])
        results = search(query, max_entries)
        return format_results(results)

    except (ImportError, Exception) as e:
        # NO fallback to full SPEEDRUN_MEMORY.md scan — that would load 67KB
        # (~9k tokens) and violates CLAUDE.md "NEVER read full SPEEDRUN_MEMORY".
        # If the FTS5 index is unavailable, surface an actionable hint instead.
        return (
            f"[SPEEDRUN index unavailable: {type(e).__name__}. "
            f"Run: python tools/speedrun_db.py rebuild]"
        )


# ---------------------------------------------------------------------------
# kb.db direct recon search (HackTricks / PayloadsAllTheThings / ExploitDB / KEV)
# ---------------------------------------------------------------------------
KB_DB_PATH = MACHINE_ROOT / "knowledge" / "kb.db"

# Category -> source_path LIKE patterns prioritized at recon
_KB_CATEGORY_PATTERNS = {
    "pwn": [
        "%binary-exploitation%",
        "%libc-heap%",
        "%rop%",
        "%stack-overflow%",
        "%format-string%",
        "%protections%",
        "%exploit%",
    ],
    "rev": [
        "%reversing%",
        "%anti-debug%",
        "%obfuscat%",
        "%binary-exploitation%",
    ],
    "web": [
        "%PayloadsAllTheThings%",
        "%pentesting-web%",
        "%web-vulns%",
        "%injection%",
    ],
    "crypto": [
        "%crypto%",
        "%cipher%",
        "%hash%",
    ],
    # Crypto subtype-specific patterns (used when crypto_subtype is known).
    # Note: HackTricks crypto coverage is limited (mostly RSA). Local `chunks`
    # (knowledge/techniques/*.md, knowledge/challenges/*.md) is the primary
    # source for ECC/lattice/PRNG/etc.
    "_crypto_rsa": [
        "%crypto\\public-key%",
        "%rsa%",
    ],
    "_crypto_ecc": [
        "%crypto\\public-key%",  # has some ECC content
        # Block: %blockchain% — "smart contract" matches Smart's attack falsely
    ],
    "_crypto_lattice": [
        "%crypto%",
    ],
    "_crypto_symmetric": [
        "%crypto\\symmetric%",
        "%cipher%",
    ],
    "_crypto_hash": [
        "%crypto\\hashes%",
        "%hash%",
    ],
    "_crypto_prng": [
        "%crypto%",  # rare in HackTricks
    ],
    "forensics": [
        "%forensic%",
        "%pcap%",
        "%memory-dump%",
        "%steganograph%",
    ],
    "web3": [
        "%blockchain%",
        "%smart-contract%",
        "%solidity%",
    ],
    "misc": [
        "%generic%",
        "%miscellaneous%",
    ],
    "ai": [
        "%AI%",
        "%llm%",
        "%prompt%",
    ],
}


def _extract_recon_keywords(category: str, challenge_dir: Path,
                            crypto_info: dict = None) -> list[str]:
    """Pull 5-10 high-signal keywords from challenge files.

    For crypto: uses detect_crypto_subtype() output (signals + params + subtype)
    to inject precise terms like 'smart attack', 'Coppersmith', 'ECDSA nonce',
    instead of relying on description text alone.
    """
    kws: list[str] = []

    # Category-specific seed terms (broad)
    seed = {
        "pwn": ["heap", "stack", "rop", "format", "uaf", "tcache", "canary", "libc", "fsop"],
        "web": ["sqli", "ssti", "xss", "ssrf", "jwt", "lfi", "rce", "deserial"],
        "crypto": ["rsa", "aes", "ecc", "lattice", "prng", "hash", "lcg"],
        "rev": ["xor", "vm", "packed", "anti-debug", "crackme"],
        "forensics": ["pcap", "memory", "stego", "carving"],
        "web3": ["solidity", "reentrancy", "delegatecall"],
    }
    seed_terms = set(seed.get(category, []))

    # CRYPTO: inject high-precision keywords from subtype detection
    # Maps each (subtype, signal/param) to specific search terms.
    CRYPTO_KW_MAP = {
        # subtype -> base terms
        "rsa": ["RSA"],
        "ecc": ["elliptic curve", "ECDLP"],
        "lattice": ["lattice", "LLL"],
        "symmetric": ["AES", "cipher"],
        "hash": ["hash", "collision"],
        "prng": ["PRNG", "random"],
        "number_theory": ["discrete log", "modular"],
    }
    # Signal -> attack name (high-signal — inject exact attack term)
    CRYPTO_SIGNAL_KW = {
        # RSA
        "dp_leaked": ["dp leak", "CRT leak"],
        "dq_leaked": ["dq leak", "CRT leak"],
        "phi_value": ["phi leaked", "totient"],
        "multi_prime": ["multi-prime RSA", "CRT decryption"],
        # ECC
        "ECDSA": ["ECDSA", "nonce reuse", "HNP"],
        "nonce_usage": ["nonce", "biased nonce"],
        "pairing": ["Weil pairing", "MOV"],
        # Lattice
        "small_roots": ["Coppersmith", "small_roots"],
        "LLL_BKZ": ["LLL", "BKZ"],
        "HNP": ["HNP", "hidden number problem"],
        "knapsack": ["knapsack", "subset sum"],
        # Symmetric
        "padding": ["padding oracle", "Vaudenay"],
        "nonce_reuse": ["nonce reuse", "keystream"],
        "ECB": ["ECB oracle"],
        "CBC": ["CBC padding"],
        # PRNG
        "MT19937": ["MT19937", "Mersenne", "untemper"],
        "LCG": ["LCG", "linear congruential"],
        "LFSR": ["LFSR", "Berlekamp-Massey"],
        # Hash
        "length_extension": ["length extension", "hashpump"],
    }
    # Param -> high-signal keyword
    CRYPTO_PARAM_KW = {
        "anomalous": ["Smart attack", "anomalous curve"],
        "supersingular": ["MOV attack", "supersingular"],
        "smooth_order": ["Pohlig-Hellman"],
        "no_validation": ["invalid curve"],
        "singular": ["singular curve"],
        "nonce_bias": ["biased nonce", "HNP", "lattice ECDSA"],
        "phi_leaked": ["phi leaked", "factor from phi"],
        "dp_leaked": ["dp leak"],
        "dq_leaked": ["dq leak"],
        "multi_n": ["common factor", "batch GCD"],
        "multi_prime": ["multi-prime"],
    }

    crypto_kws: list[str] = []
    if category == "crypto" and crypto_info:
        sub = crypto_info.get("subtype")
        if sub and sub != "unknown":
            crypto_kws.extend(CRYPTO_KW_MAP.get(sub, []))
        for sig in crypto_info.get("signals", []):
            crypto_kws.extend(CRYPTO_SIGNAL_KW.get(sig, []))
        params = crypto_info.get("params", {})
        for k, v in params.items():
            if v and k in CRYPTO_PARAM_KW:
                crypto_kws.extend(CRYPTO_PARAM_KW[k])
            # e_value specific
            if k == "e_value" and isinstance(v, int):
                if v <= 17:
                    crypto_kws.extend(["small e", "Coppersmith stereotyped"])
                elif v > 2**20:
                    crypto_kws.append("Wiener attack")
        # Dedup preserving order
        seen = set()
        crypto_kws = [k for k in crypto_kws if not (k in seen or seen.add(k))]

    # Read description files (recursive — also catches deploy/chal.py etc.)
    text_blob = ""
    desc_targets = ("challenge.md", "CHALLENGE.md", "README.md", "description.md", "meta.yaml")
    for name in desc_targets:
        p = challenge_dir / name
        if p.exists():
            try:
                text_blob += p.read_text(errors="replace")[:3000].lower() + "\n"
            except OSError:
                pass

    # CRYPTO: also scan source code for token hints (recursive)
    if category == "crypto":
        crypto_src_names = {"chall.py", "encrypt.py", "cipher.py", "rsa.py", "aes.py",
                            "server.py", "challenge.py", "prob.py", "task.py",
                            "main.py", "chal.py"}
        src_blob = ""
        for f in challenge_dir.rglob("*"):
            if not f.is_file() or ".git" in f.parts:
                continue
            if f.name in crypto_src_names or f.suffix in (".sage", ".py"):
                try:
                    src_blob += f.read_text(errors="replace")[:4000] + "\n"
                except OSError:
                    pass
            if len(src_blob) > 20000:
                break
        text_blob += "\n" + src_blob.lower()

    # Filename hints
    try:
        for f in challenge_dir.iterdir():
            text_blob += f.name.lower() + " "
    except OSError:
        pass

    found = [t for t in seed_terms if t in text_blob]
    kws.extend(found)

    # Add crypto high-signal keywords FIRST (highest priority)
    kws = crypto_kws + kws

    # Words from description (4+ chars, alpha) — last resort
    if text_blob and len(kws) < 8:
        words = re.findall(r"[a-z][a-z0-9]{3,}", text_blob)
        from collections import Counter
        stop = {"this", "that", "with", "from", "have", "your", "will", "challenge",
                "flag", "server", "given", "find", "file", "binary",
                "import", "print", "return", "class", "def", "self",
                "name", "value", "data", "remote", "host", "port", "deploy",
                "category", "platform", "status", "created", "memory",
                "solve", "artifacts"}
        common = [w for w, _ in Counter(words).most_common(20)
                  if w not in stop and w not in seed_terms and w not in {k.lower() for k in kws}]
        kws.extend(common[:5])

    # Dedup preserving order
    seen = set()
    out = []
    for k in kws:
        kl = k.lower()
        if kl not in seen:
            seen.add(kl)
            out.append(k)
    return out[:10]


def kb_recon_search(category: str, challenge_dir: Path, top: int = 5,
                    crypto_info: dict = None) -> list[dict]:
    """Direct kb.db FTS5 search prioritized by category. Returns top hits.

    Each hit: {table, source_path, heading, snippet}
    Cheap (single sqlite query per table). Used at recon, NOT counted toward
    midsolve_search call cap.

    For crypto: uses crypto_info (from detect_crypto_subtype) to:
      - Inject high-precision keywords (signal/param-driven)
      - Pick subtype-specific source_path filters
      - Prioritize chunks over external_techniques (local KB has the good stuff)
      - Block blockchain matches when subtype is ecc/lattice/prng (avoids
        "smart contract" false positives for "Smart's attack" etc.)
    """
    if not KB_DB_PATH.exists():
        return []

    import sqlite3
    keywords = _extract_recon_keywords(category, challenge_dir, crypto_info=crypto_info)
    if not keywords:
        return []

    # Build phrase-quoted FTS5 query (each keyword as exact phrase, OR'd)
    fts_query = " OR ".join(f'"{k}"' for k in keywords if len(k) > 2)
    if not fts_query:
        return []

    try:
        conn = sqlite3.connect(str(KB_DB_PATH))
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []

    hits: list[dict] = []

    # Determine source_path patterns
    patterns = _KB_CATEGORY_PATTERNS.get(category, [])
    crypto_subtype = (crypto_info or {}).get("subtype") if category == "crypto" else None
    if crypto_subtype and crypto_subtype != "unknown":
        sub_patterns = _KB_CATEGORY_PATTERNS.get(f"_crypto_{crypto_subtype}")
        if sub_patterns:
            patterns = sub_patterns  # subtype-specific overrides generic

    # Block patterns: paths to EXCLUDE from external_techniques.
    # ECC/lattice/prng searches frequently false-positive on blockchain pages
    # (e.g., "Smart's attack" on anomalous curves matches "smart contract").
    block_patterns: list[str] = []
    if category == "crypto" and crypto_subtype in ("ecc", "lattice", "prng", "hash", "number_theory"):
        block_patterns = ["%blockchain%", "%smart-contract%", "%solidity%", "%AI\\%"]

    # Decide ordering: for crypto non-RSA, chunks (local KB) is better than HackTricks
    chunks_first = False
    if category == "crypto":
        if crypto_subtype in ("ecc", "lattice", "prng", "number_theory", "symmetric", "hash"):
            chunks_first = True

    def _query_external() -> None:
        if patterns:
            like_clause = " OR ".join("source_path LIKE ?" for _ in patterns)
            block_clause = ""
            block_params: list = []
            if block_patterns:
                block_clause = " AND " + " AND ".join("source_path NOT LIKE ?" for _ in block_patterns)
                block_params = list(block_patterns)
            sql = (
                f"SELECT source_path, heading, body, rank FROM external_techniques "
                f"WHERE external_techniques MATCH ? AND ({like_clause}){block_clause} "
                f"ORDER BY rank LIMIT ?"
            )
            try:
                for row in conn.execute(sql, (fts_query, *patterns, *block_params, top)):
                    hits.append({
                        "table": "external_techniques",
                        "source_path": row["source_path"],
                        "heading": row["heading"],
                        "snippet": (row["body"] or "")[:300],
                    })
            except sqlite3.Error:
                pass

    def _query_chunks() -> None:
        try:
            for row in conn.execute(
                "SELECT source_path, heading, body, rank FROM chunks WHERE chunks MATCH ? "
                "ORDER BY rank LIMIT ?",
                (fts_query, top),
            ):
                hits.append({
                    "table": "chunks",
                    "source_path": row["source_path"],
                    "heading": row["heading"],
                    "snippet": (row["body"] or "")[:300],
                })
        except sqlite3.Error:
            pass

    if chunks_first:
        _query_chunks()
        if len(hits) < top:
            _query_external()
    else:
        _query_external()
        if len(hits) < top:
            _query_chunks()

    # Stage 3: cisa_kev for any category that may pull in named software/libraries.
    # rev/forensics often hit OpenSSL, libpng, zlib, libxml2 etc — same KEV catalog
    # is the cheapest CVE oracle we have. Skip only crypto (math-only) and ai/web3.
    if category in ("web", "pwn", "misc", "rev", "forensics") and len(hits) < top:
        try:
            for row in conn.execute(
                "SELECT cve_id, vendor, product, vulnerability_name, description, rank "
                "FROM cisa_kev WHERE cisa_kev MATCH ? ORDER BY rank LIMIT ?",
                (fts_query, max(1, top - len(hits))),
            ):
                hits.append({
                    "table": "cisa_kev",
                    "source_path": f"KEV {row['cve_id']}",
                    "heading": f"{row['vendor']} {row['product']} - {row['vulnerability_name']}",
                    "snippet": (row["description"] or "")[:300],
                })
        except sqlite3.Error:
            pass

    conn.close()
    # Dedup by source_path+heading
    seen = set()
    deduped = []
    for h in hits:
        key = (h.get("source_path"), h.get("heading"))
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    return deduped[:top]


_EXT_REPO_RE = re.compile(r"^\[([^\]]+)\]\s*(.*)$")
_EXT_REPO_ALIASES = {"PayloadsAllTheThings": "PATT", "PAT": "PATT"}


def _split_external_repo(source_path: str) -> tuple[str, str]:
    """Extract '[RepoName]' prefix from an external_techniques source_path so
    PayloadsAllTheThings vs HackTricks vs ctf-wiki are visually distinct in the
    KB shortcuts block (instead of an opaque [external] tag)."""
    if not source_path:
        return ("external", "")
    m = _EXT_REPO_RE.match(source_path)
    if not m:
        return ("external", source_path)
    label = _EXT_REPO_ALIASES.get(m.group(1).strip(), m.group(1).strip())
    return (label, m.group(2).strip())


def format_kb_shortcuts(hits: list[dict]) -> str:
    """Format kb_recon_search() output as a compact prompt block."""
    if not hits:
        return ""
    lines = ["[KB SHORTCUTS — auto-retrieved by triage.py from kb.db]"]
    lines.append(
        "These are top hits from HackTricks / PayloadsAllTheThings / ExploitDB / KEV / local writeups, "
        "prioritized by category. Read these BEFORE writing any code. They often contain the exact technique you need."
    )
    for i, h in enumerate(hits, 1):
        tag = h["table"]
        path = h["source_path"]
        # Surface the actual repo name (PATT / HackTricks / ...) for external_techniques
        # so the agent can weight payload-repo hits vs local-writeup hits at a glance.
        if tag == "external_techniques":
            tag, path = _split_external_repo(path)
        head = h.get("heading") or ""
        snip = (h.get("snippet") or "").strip().replace("\n", " ")[:280]
        lines.append(f"\n### {i}. [{tag}] {path}")
        if head:
            lines.append(f"  § {head}")
        if snip:
            lines.append(f"  {snip}")
    lines.append("\n[END KB SHORTCUTS]")
    return "\n".join(lines)


def search_knowledge(category: str, challenge_dir: Path) -> dict:
    """Search knowledge DB for similar challenges and relevant techniques.
    Returns {similar_challenges: [...], techniques: [...], decision_branches: {...}}
    """
    result = {
        "similar_challenges": [],
        "techniques": [],
        "decision_branches": [],
    }

    kb_script = MACHINE_ROOT / "tools" / "knowledge.py"
    if not kb_script.exists():
        return result

    # Build search queries from challenge content
    queries = [category]

    # Extract keywords from challenge description
    for desc_name in ("challenge.md", "CHALLENGE.md", "README.md", "description.md"):
        desc_path = challenge_dir / desc_name
        if desc_path.exists():
            try:
                text = desc_path.read_text(errors="replace")[:2000]
                # Extract meaningful words
                words = re.findall(r'[a-zA-Z]{4,}', text)
                # Take most common non-stop words
                from collections import Counter
                stop = {"this", "that", "with", "from", "your", "have", "will",
                        "been", "they", "their", "what", "when", "where", "which",
                        "there", "about", "into", "more", "some", "than", "them",
                        "each", "make", "like", "just", "over", "such", "only",
                        "also", "after", "before", "through", "between", "flag",
                        "challenge", "file", "find", "given", "server"}
                filtered = [w.lower() for w in words if w.lower() not in stop]
                common = Counter(filtered).most_common(5)
                queries.extend([w for w, _ in common])
            except OSError:
                pass
            break

    # Detect tech stack for web
    if category == "web":
        for f in challenge_dir.rglob("*"):
            if f.name == "requirements.txt":
                try:
                    deps = f.read_text(errors="replace").lower()
                    for fw in ("flask", "django", "fastapi", "express"):
                        if fw in deps:
                            queries.append(fw)
                except OSError:
                    pass
            elif f.name == "package.json":
                try:
                    pkg = json.loads(f.read_text(errors="replace"))
                    deps_all = {**pkg.get("dependencies", {}),
                                **pkg.get("devDependencies", {})}
                    for fw in ("express", "koa", "hapi", "next", "nuxt"):
                        if fw in deps_all:
                            queries.append(fw)
                except (OSError, json.JSONDecodeError):
                    pass

    # Search knowledge DB
    query_str = " ".join(queries[:8])
    try:
        out = subprocess.run(
            [sys.executable, str(kb_script), "search", query_str, "--top", "5"],
            capture_output=True, text=True, timeout=15,
            cwd=str(MACHINE_ROOT)
        )
        if out.returncode == 0:
            # Parse output: knowledge.py prints formatted results
            lines = out.stdout.strip().split("\n")
            for line in lines:
                line = line.strip()
                if not line or line.startswith("[knowledge]"):
                    continue
                # Technique results contain source_path and heading
                if "techniques/" in line:
                    result["techniques"].append(line)
                elif "challenges/" in line:
                    result["similar_challenges"].append(line)
    except Exception:
        pass

    # Get decision tree branches for this category
    try:
        from decision_tree import TREES, FRAMEWORK_VULN_PRIORITY
        if category in TREES:
            branches = {}
            for trigger, actions in TREES[category].items():
                branches[trigger] = [
                    f"{a['id']}: {a['desc']}" for a in actions[:3]
                ]
            result["decision_branches"] = branches

        # Framework vulnerability priority for web
        if category == "web":
            result["framework_priority"] = FRAMEWORK_VULN_PRIORITY
    except ImportError:
        pass

    return result


def load_technique_snippets(techniques: list, max_per_technique: int = 500) -> list:
    """Load actual content from technique files referenced in search results."""
    snippets = []
    seen_paths = set()

    for t in techniques:
        # Extract file path from search result line
        match = re.search(r'(knowledge/techniques/\S+\.md)', t)
        if not match:
            continue
        rel_path = match.group(1)
        if rel_path in seen_paths:
            continue
        seen_paths.add(rel_path)

        full_path = MACHINE_ROOT / rel_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(errors="replace")
            # Skip frontmatter
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    content = content[end + 3:].strip()
            # Truncate
            if len(content) > max_per_technique:
                content = content[:max_per_technique] + "\n[... truncated]"
            snippets.append({
                "path": rel_path,
                "content": content
            })
        except OSError:
            pass

        if len(snippets) >= 3:
            break

    return snippets


def load_similar_writeups(challenges: list, max_per: int = 400) -> list:
    """Load snippets from similar solved challenge writeups."""
    snippets = []
    seen = set()

    for c in challenges:
        match = re.search(r'(knowledge/challenges/\S+\.md)', c)
        if not match:
            continue
        rel_path = match.group(1)
        if rel_path in seen:
            continue
        seen.add(rel_path)

        full_path = MACHINE_ROOT / rel_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(errors="replace")
            # Extract key sections: Technique, Vulnerability, Key Insight
            sections = {}
            current = None
            for line in content.split("\n"):
                hm = re.match(r'^##\s+(.+)', line)
                if hm:
                    current = hm.group(1).strip().lower()
                    sections[current] = []
                elif current:
                    sections[current].append(line)

            # Build summary
            summary_parts = []
            for key in ("technique", "vulnerability", "key insight",
                        "attack flow", "solve steps"):
                if key in sections:
                    text = "\n".join(sections[key][:10]).strip()
                    if text:
                        summary_parts.append(f"**{key.title()}**: {text}")

            name = Path(rel_path).stem
            summary = "\n".join(summary_parts)[:max_per] if summary_parts else ""
            if summary:
                snippets.append({"name": name, "path": rel_path, "summary": summary})
        except OSError:
            pass

        if len(snippets) >= 3:
            break

    return snippets


# ---------------------------------------------------------------------------
# Pipeline Selection
# ---------------------------------------------------------------------------

def select_pipeline(difficulty: str) -> str:
    """Select pipeline mode based on difficulty."""
    if difficulty == "easy":
        return "lightweight"  # solver only
    elif difficulty == "medium":
        return "lightweight"  # solver + optional critic escalation
    else:
        return "full"  # solver → critic → remote-verifier


# ---------------------------------------------------------------------------
# Format Knowledge Context Block
# ---------------------------------------------------------------------------

def format_knowledge_context(knowledge: dict, technique_snippets: list,
                             challenge_snippets: list,
                             category: str, difficulty: str) -> str:
    """Format the knowledge context block that gets injected into solver prompt."""
    lines = []
    lines.append("[KNOWLEDGE CONTEXT — auto-retrieved by triage.py]")
    lines.append("")

    # Similar solved challenges
    if challenge_snippets:
        lines.append("## Similar Solved Challenges")
        for i, cs in enumerate(challenge_snippets, 1):
            lines.append(f"\n### {i}. {cs['name']} ({cs['path']})")
            lines.append(cs["summary"])
        lines.append("")

    # Relevant techniques
    if technique_snippets:
        lines.append("## Relevant Techniques")
        for i, ts in enumerate(technique_snippets, 1):
            lines.append(f"\n### {i}. {ts['path']}")
            lines.append(ts["content"])
        lines.append("")

    # Decision tree branches
    if knowledge.get("decision_branches"):
        lines.append("## Decision Tree (pre-loaded)")
        lines.append("If you get stuck, try these approaches in order:")
        for trigger, actions in knowledge["decision_branches"].items():
            lines.append(f"\n**{trigger}:**")
            for a in actions:
                lines.append(f"  - {a}")
        lines.append("")

    # Framework vulnerability priority (web only)
    if category == "web" and knowledge.get("framework_priority"):
        lines.append("## Framework Vulnerability Priority")
        for fw, vulns in knowledge["framework_priority"].items():
            lines.append(f"  {fw}: {' → '.join(vulns[:4])}")
        lines.append("")

    if not any([challenge_snippets, technique_snippets,
                knowledge.get("decision_branches")]):
        lines.append("No relevant knowledge found. Use WebSearch if stuck.")
        lines.append("")

    lines.append(f"[Difficulty: {difficulty} | Pipeline: {select_pipeline(difficulty)}]")
    lines.append("[END KNOWLEDGE CONTEXT]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main Triage
# ---------------------------------------------------------------------------

def triage(challenge_dir: str, category_hint: str = None) -> dict:
    """Run full triage on a challenge directory."""
    cdir = Path(challenge_dir).resolve()
    if not cdir.is_dir():
        return {"error": f"Not a directory: {cdir}"}

    # 1. Detect category
    category = detect_category(cdir, category_hint)

    # 1.5. Crypto sub-type detection (if crypto)
    crypto_info = {}
    if category == "crypto":
        crypto_info = detect_crypto_subtype(cdir)

    # 2. Search knowledge
    knowledge = search_knowledge(category, cdir)

    # 2.5. Search SPEEDRUN_MEMORY (selective, not full 67KB load)
    speedrun_context = search_speedrun_memory(category, cdir)

    # 2.6. Extract relevant category sections (selective, not full file)
    category_context = extract_relevant_category_sections(category, cdir)

    # 3. Load technique and challenge snippets
    technique_snippets = load_technique_snippets(knowledge["techniques"])
    challenge_snippets = load_similar_writeups(knowledge["similar_challenges"])

    # 4. Estimate difficulty (heuristic + raw signals for LLM override)
    similar_count = len(challenge_snippets)
    difficulty, difficulty_signals = estimate_difficulty(cdir, category, similar_count)
    difficulty_context = format_difficulty_signals(difficulty, difficulty_signals)

    # 5. Select pipeline
    pipeline = select_pipeline(difficulty)

    # 5.5. Direct kb.db recon — pull HackTricks/PAT/ExploitDB/KEV hits
    # Pass crypto_info so subtype-specific keywords/patterns are used
    kb_hits = kb_recon_search(category, cdir, top=5, crypto_info=crypto_info or None)
    kb_shortcuts_block = format_kb_shortcuts(kb_hits)

    # 6. Format knowledge context
    context_block = format_knowledge_context(
        knowledge, technique_snippets, challenge_snippets,
        category, difficulty
    )

    result = {
        "challenge_dir": str(cdir),
        "category": category,
        "difficulty": difficulty,
        "pipeline": pipeline,
        "similar_challenges": [cs["name"] for cs in challenge_snippets],
        "techniques": [ts["path"] for ts in technique_snippets],
        "knowledge_context": context_block,
        "kb_shortcuts": kb_shortcuts_block,
        "kb_hits": kb_hits,
        "speedrun_context": speedrun_context,
        "category_context": category_context,
        "difficulty_signals": difficulty_context,
    }

    # Add crypto-specific fields
    if crypto_info:
        result["crypto_subtype"] = crypto_info.get("subtype", "unknown")
        result["crypto_signals"] = crypto_info.get("signals", [])
        result["crypto_params"] = crypto_info.get("params", {})
        result["crypto_attacks"] = crypto_info.get("suggested_attacks", [])
        result["crypto_template"] = crypto_info.get("suggested_template")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_agent_prompt(challenge_dir: str, agent_name: str,
                       category_hint: str = None,
                       extra_context: str = "") -> str:
    """Build a compact agent prompt with dynamically injected context.
    Use this to spawn agents with only the relevant knowledge, not full files.

    Returns a prompt string ready to pass to Agent tool.

    Usage from orchestrator:
        result = triage("challenges/foo", "crypto")
        prompt = build_agent_prompt("challenges/foo", "solver", "crypto")
    """
    cdir = Path(challenge_dir).resolve()
    result = triage(challenge_dir, category_hint)

    if "error" in result:
        return f"ERROR: {result['error']}"

    category = result["category"]
    difficulty = result["difficulty"]

    parts = []
    # Line 1-2: Critical facts
    parts.append(f"[Challenge: {cdir.name} | Category: {category} | Difficulty: {difficulty}]")

    # Meta.yaml info
    meta_path = cdir / "meta.yaml"
    if meta_path.exists():
        try:
            meta_text = meta_path.read_text(errors="replace")[:300]
            parts.append(f"[META] {meta_text.strip()}")
        except OSError:
            pass

    # Crypto-specific context injection (BEFORE category context for priority)
    if category == "crypto" and result.get("crypto_subtype"):
        crypto_block = [f"\n[CRYPTO ANALYSIS — auto-detected by triage.py]"]
        crypto_block.append(f"Subtype: {result['crypto_subtype']}")
        crypto_block.append(f"Signals: {', '.join(result.get('crypto_signals', []))}")
        if result.get("crypto_params"):
            params_str = ", ".join(f"{k}={v}" for k, v in result["crypto_params"].items())
            crypto_block.append(f"Params: {params_str}")
        if result.get("crypto_attacks"):
            atk_str = " → ".join(a["id"] for a in result["crypto_attacks"][:5])
            crypto_block.append(f"Attack chain (priority order): {atk_str}")
        if result.get("crypto_template"):
            crypto_block.append(f"Template: templates/{result['crypto_template']}")
        crypto_block.append("[END CRYPTO ANALYSIS]")
        parts.append("\n".join(crypto_block))

    # Selective category context (not full file)
    if result.get("category_context"):
        parts.append(f"\n{result['category_context']}")

    # Speedrun memory (already filtered)
    if result.get("speedrun_context") and "No matching" not in result["speedrun_context"]:
        parts.append(f"\n{result['speedrun_context']}")

    # KB shortcuts (HackTricks / PayloadsAllTheThings / ExploitDB / KEV) — high priority
    if result.get("kb_shortcuts"):
        parts.append(f"\n{result['kb_shortcuts']}")

    # Knowledge context (similar challenges, techniques)
    if result.get("knowledge_context"):
        parts.append(f"\n{result['knowledge_context']}")

    # Extra context (handoff, etc.)
    if extra_context:
        parts.append(f"\n{extra_context}")

    parts.append(f"\n[Agent: {agent_name} | Pipeline: {result['pipeline']}]")
    parts.append(f"Challenge dir: {cdir}")

    return "\n".join(parts)


def main():
    # Force UTF-8 stdout so KB shortcuts containing em dashes / non-ASCII text
    # don't blow up on Windows consoles (cp949). Same fix as midsolve_search.py.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    p = argparse.ArgumentParser(description="malrang_auto_ctf Challenge Triage")
    p.add_argument("challenge_dir", help="Path to challenge directory")
    p.add_argument("--category", "-c", default=None,
                   help="Override category detection")
    p.add_argument("--context", action="store_true",
                   help="Output only the knowledge context block (for prompt injection)")
    p.add_argument("--build-prompt", metavar="AGENT",
                   help="Build compact agent prompt with dynamic context injection")
    p.add_argument("--json", action="store_true",
                   help="Output full JSON (default)")

    args = p.parse_args()

    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    # Auto-set terminal title to challenge name
    chal_name = Path(args.challenge_dir).resolve().name
    sys.stderr.write(f"\033]0;CTF: {chal_name}\007")
    sys.stderr.flush()

    if args.build_prompt:
        prompt = build_agent_prompt(args.challenge_dir, args.build_prompt, args.category)
        print(prompt)
        return

    result = triage(args.challenge_dir, args.category)

    if "error" in result:
        print(json.dumps(result), file=sys.stderr)
        sys.exit(1)

    if args.context:
        print(result["knowledge_context"])
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
