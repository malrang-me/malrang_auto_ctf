#!/usr/bin/env python3
"""Verify which blocks are truly unsatisfiable by testing with random inputs."""
import numpy as np
import sys
import time
sys.path.insert(0, '/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX')
from verify_constraints import eval_main_graph

# UNSAT blocks from Z3 analysis
alleged_unsat = [5, 11, 25, 33, 35, 36, 52, 53, 56, 72, 77, 88, 97, 131, 132, 136, 158, 184, 192, 219, 230, 254, 259, 260, 274, 282, 295, 304, 310, 313, 327, 342, 345, 363, 367, 392, 396, 405, 408, 424, 435]

# Track which blocks ever returned non-zero
block_ever_nonzero = {b: False for b in alleged_unsat}
best_per_block = {b: 0 for b in alleged_unsat}

np.random.seed(42)
start = time.time()

for trial in range(200000):
    inp = np.random.randint(0, 256, 56, dtype=np.uint8)
    block_results, total = eval_main_graph(inp)

    for b in alleged_unsat:
        if block_results[b] > 0:
            if not block_ever_nonzero[b]:
                block_ever_nonzero[b] = True
                print(f"Block {b} CAN be satisfied! (trial {trial}, result={block_results[b]})")
                # Print the input that satisfied it
                print(f"  Input: {list(inp)}")
            best_per_block[b] = max(best_per_block[b], block_results[b])

    if trial % 50000 == 49999:
        elapsed = time.time() - start
        satisfied = sum(1 for v in block_ever_nonzero.values() if v)
        print(f"After {trial+1} trials ({elapsed:.0f}s): {satisfied}/{len(alleged_unsat)} blocks satisfiable")

print(f"\n=== RESULTS ===")
truly_unsat = [b for b, v in block_ever_nonzero.items() if not v]
satisfiable = [b for b, v in block_ever_nonzero.items() if v]
print(f"Truly unsatisfiable: {len(truly_unsat)} blocks: {truly_unsat}")
print(f"Actually satisfiable: {len(satisfiable)} blocks: {satisfiable}")
