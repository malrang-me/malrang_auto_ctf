#!/usr/bin/env python3
"""
Parallel brute-force template for CTF challenges.

Supports:
  1. CPU-bound: hash cracking, key search, table inversion (multiprocessing)
  2. I/O-bound: blind SQLi, byte oracle, timing attacks (threading/async)

Usage:
  # Copy to challenge dir, customize check_candidate() and generate_candidates()
  cp templates/brute_parallel.py challenges/<name>/solve.py

Examples:
  - Hash brute: iterate keyspace, check hash match
  - Byte oracle: parallel HTTP requests with different byte values
  - Timing attack: measure response time per candidate character
"""
import os
import re
import sys
import time
import signal
import itertools
import string
from multiprocessing import Pool, cpu_count, Value
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator

FLAG_RE = re.compile(r"(DH\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\})")

# Shared flag for early termination
_found = Value('i', 0)


# ============================================================================
# CUSTOMIZE THESE FOR YOUR CHALLENGE
# ============================================================================

def check_candidate(candidate) -> str | None:
    """
    Test a single candidate. Return flag string if found, None otherwise.

    Examples:
      - Hash crack: return candidate if hashlib.md5(candidate) == target
      - Key search: return decrypt(ct, candidate) if valid padding
      - Table inversion: return answer if table[candidate] == target
    """
    # TODO: implement your check logic
    # Example: XOR brute
    # key = candidate
    # result = bytes(c ^ key for c in ciphertext)
    # if b"flag{" in result:
    #     return result.decode()
    return None


def generate_candidates() -> Iterator:
    """
    Generate candidate values to test.

    Examples:
      - Single byte: range(256)
      - 2-byte key: itertools.product(range(256), repeat=2)
      - Printable strings: itertools.product(string.printable, repeat=N)
      - Wordlist: open("rockyou.txt").readlines()
    """
    # TODO: customize for your keyspace
    # Example: single byte key
    return range(256)

    # Example: 3-byte key
    # return itertools.product(range(256), repeat=3)

    # Example: printable chars of length 4
    # return itertools.product(string.ascii_letters + string.digits, repeat=4)


# ============================================================================
# CPU-BOUND PARALLEL (multiprocessing) — hash crack, key search
# ============================================================================

def _worker_cpu(candidate):
    """Worker for multiprocessing pool."""
    if _found.value:
        return None
    result = check_candidate(candidate)
    if result:
        _found.value = 1
    return result


def brute_cpu(timeout_sec: int = 600, workers: int = 0) -> str | None:
    """
    CPU-bound parallel brute-force using multiprocessing.
    Good for: hash cracking, key search, decryption attempts.
    """
    if workers <= 0:
        workers = max(1, cpu_count() - 1)

    candidates = generate_candidates()
    total_checked = 0
    start = time.time()

    print(f"[brute-cpu] Starting with {workers} workers, timeout={timeout_sec}s")

    with Pool(workers) as pool:
        # Use imap_unordered for memory efficiency with large keyspaces
        batch_size = workers * 100
        for result in pool.imap_unordered(_worker_cpu, candidates, chunksize=batch_size):
            total_checked += 1
            if result:
                elapsed = time.time() - start
                print(f"[brute-cpu] FOUND after {total_checked} checks in {elapsed:.1f}s")
                print(f"[+] FLAG: {result}")
                pool.terminate()
                return result

            # Progress every 10k
            if total_checked % 10000 == 0:
                elapsed = time.time() - start
                rate = total_checked / max(elapsed, 0.001)
                print(f"  [{total_checked} checked, {rate:.0f}/s, {elapsed:.1f}s elapsed]")

            # Timeout
            if time.time() - start > timeout_sec:
                print(f"[brute-cpu] TIMEOUT after {total_checked} checks")
                pool.terminate()
                return None

    elapsed = time.time() - start
    print(f"[brute-cpu] Exhausted keyspace: {total_checked} checked in {elapsed:.1f}s")
    return None


# ============================================================================
# I/O-BOUND PARALLEL (threading) — blind SQLi, byte oracle, network brute
# ============================================================================

def check_candidate_io(candidate) -> str | None:
    """
    I/O-bound candidate check (network request).
    Override this for remote oracle attacks.

    Example (blind SQLi byte oracle):
      import requests
      payload = f"' OR (SELECT ASCII(SUBSTR(flag,{pos},1)) FROM flags)={candidate}--"
      r = requests.get(url, params={"q": payload}, timeout=5)
      return "found" if "Welcome" in r.text else None
    """
    # TODO: implement your I/O check
    return None


def brute_io(timeout_sec: int = 300, workers: int = 10) -> str | None:
    """
    I/O-bound parallel brute-force using threading.
    Good for: blind SQLi, byte-by-byte oracle, timing attacks.
    """
    candidates = list(generate_candidates())
    start = time.time()

    print(f"[brute-io] Starting with {workers} threads, {len(candidates)} candidates, timeout={timeout_sec}s")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for c in candidates:
            if time.time() - start > timeout_sec:
                break
            futures[executor.submit(check_candidate_io, c)] = c

        for future in as_completed(futures, timeout=timeout_sec):
            try:
                result = future.result(timeout=5)
                if result:
                    elapsed = time.time() - start
                    print(f"[brute-io] FOUND in {elapsed:.1f}s")
                    print(f"[+] FLAG: {result}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    return result
            except Exception:
                pass

    print(f"[brute-io] No result found")
    return None


# ============================================================================
# BYTE-BY-BYTE ORACLE — character-at-a-time attacks
# ============================================================================

def oracle_check(known: str, test_char: str, position: int) -> bool:
    """
    Test if test_char is correct at the given position.
    Override for your specific oracle.

    Examples:
      - Timing: correct char takes longer
      - Response diff: correct char gives different status code
      - Error position: error message reveals which char is wrong
    """
    # TODO: implement oracle
    return False


def brute_byte_by_byte(flag_len: int = 32, charset: str = "", prefix: str = "",
                       timeout_sec: int = 300, threads_per_pos: int = 5) -> str | None:
    """
    Byte-by-byte parallel oracle attack.
    At each position, test all charset chars in parallel.
    """
    if not charset:
        charset = string.printable.strip()

    flag = list(prefix)
    start = time.time()

    print(f"[oracle] Byte-by-byte, len={flag_len}, charset={len(charset)} chars, prefix='{prefix}'")

    for pos in range(len(prefix), flag_len):
        if time.time() - start > timeout_sec:
            print(f"[oracle] TIMEOUT at position {pos}")
            break

        best_char = None

        with ThreadPoolExecutor(max_workers=threads_per_pos) as executor:
            futures = {
                executor.submit(oracle_check, "".join(flag), c, pos): c
                for c in charset
            }
            for future in as_completed(futures, timeout=30):
                c = futures[future]
                try:
                    if future.result():
                        best_char = c
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                except Exception:
                    pass

        if best_char:
            flag.append(best_char)
            print(f"  [{pos:2d}] '{best_char}' -> {''.join(flag)}")
        else:
            print(f"  [{pos:2d}] No match found, stopping")
            break

    result = "".join(flag)
    if len(result) >= flag_len:
        print(f"[+] FLAG: {result}")
    return result


# ============================================================================
# MAIN — auto-select mode
# ============================================================================

def solve():
    mode = os.environ.get("BRUTE_MODE", "cpu")
    timeout = int(os.environ.get("BRUTE_TIMEOUT", "600"))

    if mode == "cpu":
        return brute_cpu(timeout_sec=timeout)
    elif mode == "io":
        return brute_io(timeout_sec=timeout)
    elif mode == "oracle":
        prefix = os.environ.get("FLAG_PREFIX", "")
        flag_len = int(os.environ.get("FLAG_LEN", "32"))
        return brute_byte_by_byte(flag_len=flag_len, prefix=prefix, timeout_sec=timeout)
    else:
        print(f"Unknown mode: {mode}. Use BRUTE_MODE=cpu|io|oracle")
        return None


if __name__ == "__main__":
    result = solve()
    sys.exit(0 if result else 1)
