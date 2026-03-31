#!/usr/bin/env python3
"""
Optimized solver: extract per-block dependencies, use incremental evaluation.
"""
import onnx
from onnx import numpy_helper
import numpy as np
import time
import random
import sys

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    init_map[init.name] = int(numpy_helper.to_array(init).item())

# Extract block info: which input positions each block depends on
def get_gather_indices(sg):
    """Get all input indices accessed by a subgraph."""
    indices = set()
    for node in sg.node:
        if node.op_type == 'Gather':
            idx_name = node.input[1]
            if idx_name in init_map:
                indices.add(init_map[idx_name])
            # Check local constants
            for n2 in sg.node:
                if n2.op_type == 'Constant' and n2.output[0] == idx_name:
                    for attr in n2.attribute:
                        if attr.name == 'value':
                            indices.add(int(numpy_helper.to_array(attr.t).item()))
        elif node.op_type == 'If':
            for attr in node.attribute:
                if attr.g:
                    indices.update(get_gather_indices(attr.g))
    return indices

# Build block info
blocks_info = []  # (pre_node_indices, if_node, dependencies)
current_pre = []
for node in graph.node:
    if node.op_type in ('Cast', 'Reshape', 'Concat', 'ReduceSum'):
        continue
    if node.op_type == 'If':
        # Get dependencies from pre-nodes
        deps = set()
        for n in current_pre:
            if n.op_type == 'Gather':
                idx_name = n.input[1]
                if idx_name in init_map:
                    deps.add(init_map[idx_name])
        # Get dependencies from If subgraphs
        for attr in node.attribute:
            if attr.g:
                deps.update(get_gather_indices(attr.g))
        blocks_info.append(deps)
        current_pre = []
    else:
        current_pre.append(node)

print(f"Blocks: {len(blocks_info)}")
avg_deps = sum(len(d) for d in blocks_info) / len(blocks_info)
print(f"Avg dependencies per block: {avg_deps:.1f}")

# Build reverse map: position -> list of block indices
pos_to_blocks = [[] for _ in range(56)]
for bi, deps in enumerate(blocks_info):
    for pos in deps:
        if 0 <= pos < 56:
            pos_to_blocks[pos].append(bi)

print(f"Blocks per position: {[len(b) for b in pos_to_blocks]}")

# Now use ONNX for evaluation but with smarter search
import onnxruntime as ort
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name

def score(inp):
    return int(sess.run([oname], {iname: np.array(inp, dtype=np.uint8)})[0])

# Use compiled manual evaluator for per-block scores
sys.path.insert(0, '/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX')
from verify_constraints import eval_main_graph

def block_scores(inp):
    br, total = eval_main_graph(np.array(inp, dtype=np.uint8))
    return br, total

# Phase 1: Smart initialization
print("\n=== Phase 1: Finding good start ===")
best = [80] * 56
best_score = score(best)
print(f"All 80: {best_score}")

# Try different constant values
for v in range(256):
    t = [v] * 56
    s = score(t)
    if s > best_score:
        best_score = s
        best = t[:]
        print(f"  All {v}: {s}")

print(f"Best constant: {best_score} (value={best[0]})")

# Phase 2: Position-by-position optimization
# For each position, find the value that gives the best score
# Use ONNX runtime for total score (faster than per-block evaluation)
print("\n=== Phase 2: Hill Climbing ===")
start = time.time()

for iteration in range(50):
    improved = False
    positions = list(range(56))
    random.shuffle(positions)

    for pos in positions:
        old = best[pos]
        best_v = old
        best_s = best_score

        # Evaluate all 256 values for this position
        for v in range(256):
            if v == old: continue
            best[pos] = v
            s = score(best)
            if s > best_s:
                best_s = s
                best_v = v

        best[pos] = best_v
        if best_s > best_score:
            best_score = best_s
            improved = True

    elapsed = time.time() - start
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
    print(f"  iter {iteration}: score={best_score}/2563 time={elapsed:.0f}s")

    if best_score == 2563:
        print("*** PERFECT SCORE ***")
        break
    if not improved:
        print("  Converged!")
        break

flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
print(f"\n=== RESULT ===")
print(f"Score: {best_score}/2563")
print(f"Flag: {flag}")
print(f"Bytes: {best}")
