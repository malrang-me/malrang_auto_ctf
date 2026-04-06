#!/usr/bin/env python3
"""
angr symbolic execution solver template for CTF reversing challenges.

Features:
  - Path explosion prevention (DFS, state limit, loop bound, memory cap)
  - Auto-detect find/avoid from strings + xrefs
  - stdin / argv / file input modes
  - stdout-based success check
  - Incremental constraint logging for debugging
  - Timeout with graceful partial output

Usage:
  wsl python3 templates/angr_solve.py ./binary --find 0x401234 --avoid 0x401300
  wsl python3 templates/angr_solve.py ./binary --auto
  wsl python3 templates/angr_solve.py ./binary --auto --dfs --max-states 50000
  wsl python3 templates/angr_solve.py ./binary --stdout "Correct" --len 16

Requires: pip install angr (WSL recommended)
"""
import angr
import claripy
import sys
import os
import argparse
import re
import signal
import time
import logging

# Suppress angr's verbose output
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

# ============================================================================
# Path Explosion Prevention Configuration
# ============================================================================

DEFAULT_CONFIG = {
    "max_states": 100000,     # Hard limit on active states
    "max_time": 300,          # Timeout in seconds
    "max_memory_mb": 4096,    # Memory cap (MB)
    "loop_bound": 256,        # Max loop iterations (prevents infinite loops)
    "use_dfs": False,         # DFS strategy (less memory than BFS)
    "use_lazy_solves": True,  # Defer constraint solving (faster exploration)
    "use_veritesting": False, # Merge states at convergence points (can help CFF)
    "concretize_threshold": 128,  # Concretize symbolic data > N bytes
}


# ============================================================================
# Core Solver
# ============================================================================

def solve_flag_checker(binary_path, find_addr=None, avoid_addrs=None,
                       flag_len=32, flag_prefix=b"", input_mode="stdin",
                       auto_detect=False, success_output=b"",
                       config=None):
    """
    Solve a flag checker binary using angr symbolic execution.

    Args:
        binary_path: Path to the target binary
        find_addr: Address(es) to reach (int or list)
        avoid_addrs: Addresses to avoid (list)
        flag_len: Expected flag length
        flag_prefix: Known flag prefix (e.g., b"DH{")
        input_mode: "stdin", "argv", or "file"
        auto_detect: Auto-detect find/avoid from strings
        success_output: Check stdout for this string instead of address
        config: Override DEFAULT_CONFIG values
    """
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    print(f"[angr] Binary: {binary_path} ({proj.arch.name})")

    # Auto-detect targets
    if auto_detect and find_addr is None:
        find_addr, avoid_addrs = _auto_detect_targets(proj)
        if find_addr is None and not success_output:
            print("[angr] Auto-detect failed. Provide --find/--avoid or --stdout.")
            return None

    # Create symbolic input
    flag_chars = [claripy.BVS(f"f{i}", 8) for i in range(flag_len)]
    flag_bv = claripy.Concat(*flag_chars)

    if input_mode == "stdin":
        state = proj.factory.entry_state(
            stdin=angr.SimFileStream(name="stdin", content=flag_bv, has_end=True),
            add_options=_build_options(cfg),
            remove_options=_build_remove_options(cfg),
        )
    elif input_mode == "argv":
        state = proj.factory.entry_state(
            args=[binary_path, flag_bv],
            add_options=_build_options(cfg),
            remove_options=_build_remove_options(cfg),
        )
    elif input_mode == "file":
        # Write symbolic data to a file, binary reads it
        simfile = angr.SimFile("input.txt", content=flag_bv, has_end=True)
        state = proj.factory.entry_state(
            add_options=_build_options(cfg),
            remove_options=_build_remove_options(cfg),
        )
        state.fs.insert("input.txt", simfile)
    else:
        raise ValueError(f"Unknown input_mode: {input_mode}")

    # Apply constraints: printable ASCII
    for c in flag_chars:
        state.solver.add(c >= 0x20, c <= 0x7e)

    # Apply prefix constraints
    for i, byte_val in enumerate(flag_prefix):
        if i < len(flag_chars):
            state.solver.add(flag_chars[i] == byte_val)

    # Loop bounding
    if cfg["loop_bound"]:
        state.options.add(angr.options.EFFICIENT_STATE_MERGING)

    # Build simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Apply DFS strategy for memory efficiency
    if cfg["use_dfs"]:
        simgr.use_technique(angr.exploration_techniques.DFS())
        print(f"[angr] Using DFS strategy")

    # Apply loop bounding
    if cfg["loop_bound"]:
        simgr.use_technique(angr.exploration_techniques.LoopSeer(
            cfg=proj.analyses.CFGFast(),
            bound=cfg["loop_bound"],
        ))
        print(f"[angr] Loop bound: {cfg['loop_bound']}")

    # Apply veritesting (merges states at convergence points)
    if cfg["use_veritesting"]:
        simgr.use_technique(angr.exploration_techniques.Veritesting())
        print(f"[angr] Veritesting enabled")

    # Set up exploration target
    find_target = find_addr
    avoid_target = avoid_addrs or []

    if success_output:
        def check_stdout(s):
            out = s.posix.dumps(1)
            return success_output in out
        find_target = check_stdout
        print(f"[angr] Exploring... stdout check: {success_output!r}")
    else:
        find_list = [find_addr] if isinstance(find_addr, int) else (find_addr or [])
        print(f"[angr] Exploring... find={[hex(a) for a in find_list]}, "
              f"avoid={[hex(a) for a in avoid_target]}")

    # Explore with progress monitoring
    found = _explore_with_monitor(simgr, find_target, avoid_target, cfg, start_time)

    if found:
        solution = found.solver.eval(flag_bv, cast_to=bytes)
        flag_str = solution.decode("latin-1").rstrip("\x00")
        stdout = found.posix.dumps(1).decode("latin-1", errors="replace")

        elapsed = time.time() - start_time
        print(f"\n[angr] SOLVED in {elapsed:.1f}s")
        print(f"[angr] FLAG: {flag_str}")
        if stdout.strip():
            print(f"[angr] stdout: {stdout[:200]}")
        return flag_str
    else:
        elapsed = time.time() - start_time
        print(f"\n[angr] No solution found after {elapsed:.1f}s")
        _print_diagnostic(simgr)
        return None


# ============================================================================
# Path Explosion Prevention
# ============================================================================

def _build_options(cfg):
    """Build angr state options for explosion prevention."""
    opts = set()
    if cfg["use_lazy_solves"]:
        opts.add(angr.options.LAZY_SOLVES)
    # Avoid symbolic lengths (common source of explosion)
    opts.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    opts.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    return opts


def _build_remove_options(cfg):
    """Remove options that cause state explosion."""
    opts = set()
    # Remove options that slow down exploration
    opts.add(angr.options.SIMPLIFY_CONSTRAINTS)  # expensive, defer to lazy
    return opts


def _explore_with_monitor(simgr, find, avoid, cfg, start_time):
    """Explore with progress monitoring, state limits, and timeout."""
    max_states = cfg["max_states"]
    max_time = cfg["max_time"]
    max_mem = cfg["max_memory_mb"]
    last_report = 0
    step_count = 0

    while simgr.active:
        simgr.step()
        step_count += 1
        elapsed = time.time() - start_time

        # Check for found states
        if find is not None:
            # Apply find/avoid filtering
            if callable(find):
                new_found = [s for s in simgr.active if find(s)]
                if new_found:
                    return new_found[0]
            else:
                # Move matching states to found stash
                simgr.move(from_stash="active", to_stash="found",
                          filter_func=lambda s: s.addr in ([find] if isinstance(find, int) else find))
                # Move avoid states
                if avoid:
                    simgr.move(from_stash="active", to_stash="avoid",
                              filter_func=lambda s: s.addr in avoid)

        if simgr.found:
            return simgr.found[0]

        # Progress report every 5 seconds
        if elapsed - last_report >= 5:
            active = len(simgr.active)
            dead = len(simgr.deadended) if hasattr(simgr, '_stashes') and 'deadended' in simgr._stashes else 0
            avoided = len(simgr.avoid) if hasattr(simgr, '_stashes') and 'avoid' in simgr._stashes else 0
            mem_mb = _get_memory_mb()
            print(f"  [{elapsed:5.1f}s] step={step_count} active={active} dead={dead} "
                  f"avoided={avoided} mem={mem_mb}MB")
            last_report = elapsed

        # State explosion check
        if len(simgr.active) > max_states:
            print(f"[angr] STATE LIMIT: {len(simgr.active)} > {max_states}. Pruning...")
            # Keep only the most promising states (closest to find addr)
            if isinstance(find, int):
                simgr.active = sorted(simgr.active,
                    key=lambda s: abs(s.addr - find))[:max_states // 2]
            else:
                simgr.active = simgr.active[:max_states // 2]

        # Timeout check
        if elapsed > max_time:
            print(f"[angr] TIMEOUT: {elapsed:.0f}s > {max_time}s")
            break

        # Memory check
        mem_mb = _get_memory_mb()
        if mem_mb > max_mem:
            print(f"[angr] MEMORY LIMIT: {mem_mb}MB > {max_mem}MB")
            break

    return None


def _get_memory_mb():
    """Get current process memory usage in MB."""
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
    except ImportError:
        try:
            import psutil
            return psutil.Process().memory_info().rss // (1024 * 1024)
        except ImportError:
            return 0


def _print_diagnostic(simgr):
    """Print diagnostic info when exploration fails."""
    print(f"  Active: {len(simgr.active)}")
    if hasattr(simgr, '_stashes'):
        for name, stash in simgr._stashes.items():
            if stash and name != 'active':
                print(f"  {name}: {len(stash)}")

    if simgr.active:
        print(f"  Active state addresses: {[hex(s.addr) for s in simgr.active[:5]]}")
    if simgr.deadended:
        print(f"  Deadended at: {[hex(s.addr) for s in simgr.deadended[:5]]}")

    print("\n  Suggestions:")
    print("    1. Try --dfs for memory-efficient depth-first search")
    print("    2. Increase --max-states (default 100000)")
    print("    3. Add more --avoid addresses to prune dead paths")
    print("    4. Check --len matches actual input length")
    print("    5. Try --veritesting for obfuscated binaries")


# ============================================================================
# Auto-detect find/avoid
# ============================================================================

def _auto_detect_targets(proj):
    """Auto-detect find/avoid addresses from string references."""
    print("[angr] Auto-detecting targets...")
    cfg = proj.analyses.CFGFast()

    find_patterns = [b"correct", b"success", b"win", b"flag{", b"DH{",
                     b"congratul", b"yes!", b"right", b"good"]
    avoid_patterns = [b"wrong", b"fail", b"incorrect", b"no!", b"error",
                      b"lose", b"bad", b"invalid", b"denied", b"nope"]

    find_addr = None
    avoid_addrs = []

    # Search string references in sections
    for section in proj.loader.main_object.sections:
        if section.name not in (".rodata", ".data", ".rdata"):
            continue
        try:
            data = proj.loader.memory.load(section.vaddr, section.memsize)
        except Exception:
            continue

        for pattern in find_patterns:
            idx = data.lower().find(pattern)
            if idx >= 0:
                str_addr = section.vaddr + idx
                # Find xrefs to this string address
                xrefs = _find_string_xrefs(proj, cfg, str_addr)
                if xrefs:
                    find_addr = xrefs[0]
                    print(f"  [find] '{pattern.decode()}' at 0x{str_addr:x} -> xref at 0x{find_addr:x}")

        for pattern in avoid_patterns:
            idx = data.lower().find(pattern)
            if idx >= 0:
                str_addr = section.vaddr + idx
                xrefs = _find_string_xrefs(proj, cfg, str_addr)
                for xref in xrefs:
                    avoid_addrs.append(xref)
                    print(f"  [avoid] '{pattern.decode()}' at 0x{str_addr:x} -> xref at 0x{xref:x}")

    # Deduplicate
    avoid_addrs = list(set(avoid_addrs))
    if find_addr in avoid_addrs:
        avoid_addrs.remove(find_addr)

    return find_addr, avoid_addrs


def _find_string_xrefs(proj, cfg, str_addr):
    """Find code locations that reference a string address."""
    xrefs = []
    for func in cfg.kb.functions.values():
        try:
            for block in func.blocks:
                for insn in block.capstone.insns:
                    for op in insn.operands:
                        if hasattr(op, 'imm') and op.imm == str_addr:
                            xrefs.append(insn.address)
                        elif hasattr(op, 'mem') and hasattr(op.mem, 'disp') and op.mem.disp == str_addr:
                            xrefs.append(insn.address)
        except Exception:
            continue
    # Also check immediate values in instructions via proj.loader
    if not xrefs:
        # Fallback: return function entry points that contain the reference
        for func in cfg.kb.functions.values():
            if func.addr and str_addr in range(func.addr - 0x1000, func.addr + func.size + 0x1000):
                xrefs.append(func.addr)
    return xrefs[:3]


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="angr CTF solver with explosion prevention")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--find", type=lambda x: int(x, 0), help="Target address (hex)")
    parser.add_argument("--avoid", type=lambda x: int(x, 0), nargs="*", default=[], help="Avoid addresses")
    parser.add_argument("--auto", action="store_true", help="Auto-detect find/avoid from strings")
    parser.add_argument("--len", type=int, default=32, help="Flag length")
    parser.add_argument("--prefix", default="", help="Known flag prefix")
    parser.add_argument("--stdout", default="", help="Success stdout string")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout seconds")
    parser.add_argument("--input-mode", choices=["stdin", "argv", "file"], default="stdin",
                       help="Input method")

    # Explosion prevention options
    parser.add_argument("--dfs", action="store_true", help="Use DFS (less memory)")
    parser.add_argument("--veritesting", action="store_true", help="Enable veritesting (helps CFF)")
    parser.add_argument("--max-states", type=int, default=100000, help="Max active states")
    parser.add_argument("--max-memory", type=int, default=4096, help="Max memory (MB)")
    parser.add_argument("--loop-bound", type=int, default=256, help="Max loop iterations")
    parser.add_argument("--no-lazy", action="store_true", help="Disable lazy solves")

    args = parser.parse_args()

    config = {
        "max_states": args.max_states,
        "max_time": args.timeout,
        "max_memory_mb": args.max_memory,
        "loop_bound": args.loop_bound,
        "use_dfs": args.dfs,
        "use_lazy_solves": not args.no_lazy,
        "use_veritesting": args.veritesting,
    }

    solve_flag_checker(
        args.binary,
        find_addr=args.find,
        avoid_addrs=args.avoid or None,
        flag_len=args.len,
        flag_prefix=args.prefix.encode() if args.prefix else b"",
        input_mode=args.input_mode,
        auto_detect=args.auto,
        success_output=args.stdout.encode() if args.stdout else b"",
        config=config,
    )
