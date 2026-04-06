#!/usr/bin/env python3
"""
Interactive reversing challenge template.

For challenges that send binaries/data over network and expect
computed answers back (e.g., On_Labor_and_Automation_2 style).

Usage:
  Customize solve_round() for your specific challenge.
"""
import os
import sys
import time
import base64
import struct
import socket

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", "1337"))
TOTAL_ROUNDS = 50
TIMEOUT = 30


def recv_until(sock, marker: bytes, timeout: int = TIMEOUT) -> bytes:
    """Receive data until marker is found or timeout."""
    data = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if marker in data:
                break
        except socket.timeout:
            break
    return data


def recv_all(sock, timeout: int = 5) -> bytes:
    """Receive all available data."""
    data = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def extract_b64_elf(text: str, marker: str = "Binary (base64):") -> bytes:
    """Extract base64-encoded binary from server response."""
    for line in text.split("\n"):
        if marker in line:
            b64 = line.split(marker)[1].strip()
            return base64.b64decode(b64)
    return b""


def parse_elf_symbols(elf_data: bytes, target_names: list[str]) -> dict:
    """Parse ELF symbol table and extract named symbols.

    Returns: {name: (file_offset, size)} for each found symbol.
    """
    # ELF header
    e_shoff = struct.unpack_from('<Q', elf_data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', elf_data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', elf_data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', elf_data, 0x3e)[0]

    # Section header string table
    shstr_off = struct.unpack_from('<Q', elf_data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    shstr_sz = struct.unpack_from('<Q', elf_data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]
    shstrtab = elf_data[shstr_off:shstr_off + shstr_sz]

    # Parse sections
    sections = {}
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', elf_data, sh)[0]
        sh_addr = struct.unpack_from('<Q', elf_data, sh + 0x10)[0]
        sh_file_off = struct.unpack_from('<Q', elf_data, sh + 0x18)[0]
        sh_sz = struct.unpack_from('<Q', elf_data, sh + 0x20)[0]
        name_end = shstrtab.index(b'\x00', name_off)
        name = shstrtab[name_off:name_end].decode()
        sections[name] = (sh_addr, sh_file_off, sh_sz)

    # VA base from .data
    if '.data' in sections:
        data_addr, data_off, _ = sections['.data']
        va_base = data_addr - data_off
    else:
        va_base = 0

    # Parse symtab
    result = {}
    if '.symtab' in sections and '.strtab' in sections:
        _, symtab_off, symtab_sz = sections['.symtab']
        _, strtab_off, strtab_sz = sections['.strtab']
        strtab = elf_data[strtab_off:strtab_off + strtab_sz]

        for i in range(symtab_sz // 24):
            off = symtab_off + i * 24
            st_name = struct.unpack_from('<I', elf_data, off)[0]
            st_value = struct.unpack_from('<Q', elf_data, off + 8)[0]
            st_size = struct.unpack_from('<Q', elf_data, off + 16)[0]
            if st_value == 0:
                continue
            name_end = strtab.index(b'\x00', st_name)
            name = strtab[st_name:name_end].decode()
            if name in target_names:
                file_off = st_value - va_base
                result[name] = (file_off, st_size)

    return result


def solve_round(data: bytes) -> str:
    """
    Solve a single round. Override this for your specific challenge.

    Args:
        data: The binary/data received for this round
    Returns:
        Answer string to send back
    """
    # Example: table lookup inversion (On_Labor_and_Automation_2 pattern)
    symbols = parse_elf_symbols(data, ["table1", "table2", "key"])

    t1_off, _ = symbols["table1"]
    t2_off, _ = symbols["table2"]
    key_off, key_sz = symbols["key"]

    table1 = [struct.unpack_from('<i', data, t1_off + j * 4)[0] for j in range(256)]
    table2 = [struct.unpack_from('<i', data, t2_off + j * 4)[0] for j in range(256)]
    key = list(data[key_off:key_off + key_sz])

    answers = []
    for i in range(len(key)):
        for x in range(256):
            if table1[table2[x]] == key[i]:
                answers.append(x)
                break
        else:
            raise ValueError(f"No solution for key[{i}]={key[i]}")

    return " ".join(map(str, answers))


def main():
    print(f"[*] Connecting to {HOST}:{PORT}")
    s = socket.socket()
    s.connect((HOST, int(PORT)))

    buf = recv_until(s, b"Enter", timeout=15)
    print(buf.decode("utf-8", errors="replace")[:300])

    for rnd in range(1, TOTAL_ROUNDS + 1):
        text = buf.decode("utf-8", errors="replace")

        # Extract binary data (customize marker for your challenge)
        elf_data = extract_b64_elf(text)
        if not elf_data:
            print(f"[!] Round {rnd}: Could not extract data")
            print(text[:500])
            break

        answer = solve_round(elf_data)
        print(f"[Round {rnd}/{TOTAL_ROUNDS}] Sending: {answer[:60]}{'...' if len(answer) > 60 else ''}")

        s.send((answer + "\n").encode())
        buf = recv_until(s, b"Enter", timeout=TIMEOUT)
        resp = buf.decode("utf-8", errors="replace")

        # Check for flag
        import re
        flag_match = re.search(r'(DH|FLAG|flag|CTF)\{[^}]+\}', resp)
        if flag_match:
            print(f"\n[!] FLAG FOUND: {flag_match.group(0)}")
            print(resp)
            break

        if "Correct" in resp or "correct" in resp:
            print(f"  -> Correct!")
        elif "Wrong" in resp or "Fail" in resp:
            print(f"  -> WRONG")
            print(resp[:300])
            break

        if rnd == TOTAL_ROUNDS:
            final = recv_all(s, timeout=10)
            print(f"[*] Final: {final.decode('utf-8', errors='replace')}")

    s.close()


if __name__ == "__main__":
    main()
