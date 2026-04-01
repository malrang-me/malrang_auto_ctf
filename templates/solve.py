#!/usr/bin/env python3
"""Solver template for crypto / rev / web3 / forensics / ai / misc challenges."""
import os
import re
import sys

HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "0"))

# Flag extraction pattern — adjust per CTF platform
FLAG_RE = re.compile(r"(DH\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\})")


def remote_connect():
    """Connect to remote target. Returns pwntools tube or socket."""
    if not HOST or not PORT:
        return None
    try:
        from pwn import remote
        return remote(HOST, PORT)
    except ImportError:
        import socket
        s = socket.create_connection((HOST, PORT), timeout=10)
        return s


def extract_flag(text: str) -> str | None:
    """Extract flag from text using common patterns."""
    m = FLAG_RE.search(text)
    return m.group(1) if m else None


def solve():
    """Main solver logic."""
    # TODO: implement solver

    # Example: remote interaction
    # r = remote_connect()
    # if r:
    #     data = r.recvall(timeout=5).decode()
    #     flag = extract_flag(data)

    # Example: local file processing
    # with open("output.txt") as f:
    #     flag = extract_flag(f.read())

    flag = None
    if flag:
        print(f"[+] FLAG: {flag}")
    else:
        print("[-] No flag found")

    return flag


if __name__ == "__main__":
    result = solve()
    sys.exit(0 if result else 1)
