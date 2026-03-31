#!/usr/bin/env python3
"""
On_Labor_and_Automation_2 solver
Algorithm: table1[table2[input[i]]] == key[i] for i in range(len(key))
Strategy: brute-force inversion - for each key byte find x in 0..255 satisfying the equation
"""

import socket
import base64
import struct
import time
import sys

HOST = 'host8.dreamhack.games'
PORT = 22254


def extract_tables_and_key(elf_data):
    """Parse ELF, find table1/table2/key via symbol table."""
    # ELF header fields
    e_shoff = struct.unpack_from('<Q', elf_data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', elf_data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', elf_data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', elf_data, 0x3e)[0]

    # Section header string table
    shstr_entry = e_shoff + e_shstrndx * e_shentsize
    sh_offset = struct.unpack_from('<Q', elf_data, shstr_entry + 0x18)[0]
    sh_size = struct.unpack_from('<Q', elf_data, shstr_entry + 0x20)[0]
    shstrtab = elf_data[sh_offset:sh_offset + sh_size]

    # Parse all section headers
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

    # Compute VA->file offset base from .data section
    data_addr, data_off, _ = sections['.data']
    va_base = data_addr - data_off

    # Parse symbol table
    symtab_addr, symtab_off, symtab_sz = sections['.symtab']
    strtab_addr, strtab_off, strtab_sz = sections['.strtab']
    strtab = elf_data[strtab_off:strtab_off + strtab_sz]

    target_syms = {}
    for i in range(symtab_sz // 24):
        off = symtab_off + i * 24
        st_name = struct.unpack_from('<I', elf_data, off)[0]
        st_value = struct.unpack_from('<Q', elf_data, off + 8)[0]
        st_size = struct.unpack_from('<Q', elf_data, off + 16)[0]
        if st_value == 0:
            continue
        name_end = strtab.index(b'\x00', st_name)
        name = strtab[st_name:name_end].decode()
        if name in ('table1', 'table2', 'key'):
            file_off = st_value - va_base
            target_syms[name] = (file_off, st_size)

    table1_off, _ = target_syms['table1']
    table2_off, _ = target_syms['table2']
    key_off, key_sz = target_syms['key']

    table1 = [struct.unpack_from('<i', elf_data, table1_off + j * 4)[0] for j in range(256)]
    table2 = [struct.unpack_from('<i', elf_data, table2_off + j * 4)[0] for j in range(256)]
    key = list(elf_data[key_off:key_off + key_sz])

    return table1, table2, key


def solve_elf(elf_data):
    """Return space-separated integer string that satisfies the validation."""
    table1, table2, key = extract_tables_and_key(elf_data)
    answers = []
    for i in range(len(key)):
        target = key[i]
        found = -1
        for x in range(256):
            if table1[table2[x]] == target:
                found = x
                break
        if found == -1:
            raise ValueError(f'No solution for key[{i}]={target}')
        answers.append(found)
    return ' '.join(map(str, answers))


def recv_until(s, marker, timeout=30):
    data = b''
    deadline = time.time() + timeout
    while time.time() < deadline:
        s.settimeout(deadline - time.time())
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if marker in data:
                break
        except socket.timeout:
            break
    return data


def main():
    print(f'Connecting to {HOST}:{PORT}')
    s = socket.socket()
    s.connect((HOST, PORT))

    # Read welcome message and first round
    buf = recv_until(s, b'Enter the correct input', timeout=15)
    print(buf.decode('utf-8', errors='replace')[:300])

    for round_num in range(1, 51):
        # Extract base64 from current buffer
        text = buf.decode('utf-8', errors='replace')
        b64 = None
        for line in text.split('\n'):
            if 'Binary (base64):' in line:
                b64 = line.split('Binary (base64):')[1].strip()

        if not b64:
            print(f'ERROR: Could not find base64 in round {round_num}')
            print('Buffer:', repr(buf[-500:]))
            break

        # Decode and solve
        elf_data = base64.b64decode(b64)
        answer = solve_elf(elf_data)
        print(f'Round {round_num}/50: sending {answer[:60]}{"..." if len(answer) > 60 else ""}')

        s.send((answer + '\n').encode())

        # Read response
        buf = recv_until(s, b'Enter the correct input', timeout=20)
        resp_text = buf.decode('utf-8', errors='replace')

        if 'Correct' in resp_text:
            print(f'  -> Correct!')
        elif 'flag' in resp_text.lower() or 'DH{' in resp_text:
            print(f'  -> FLAG FOUND!')
            print(resp_text)
            break
        elif 'Wrong' in resp_text or 'Fail' in resp_text or 'FAIL' in resp_text:
            print(f'  -> WRONG ANSWER')
            print(resp_text[:300])
            break

        # Check if we got a flag (no next round prompt)
        if round_num == 50:
            print('Completed all 50 rounds!')
            # Read any remaining output
            final = recv_until(s, b'flag', timeout=10)
            print(final.decode('utf-8', errors='replace'))
            break

    s.close()


if __name__ == '__main__':
    main()
