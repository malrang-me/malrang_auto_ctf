#!/usr/bin/env python3
"""
Z3 solver - only satisfiable constraints, then verify and hill climb the rest.
"""
import onnx
from onnx import numpy_helper
from z3 import *
import numpy as np
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_map[init.name] = int(arr.item())

x = [BitVec(f'x{i}', 32) for i in range(56)]

def get_val(name, env):
    if name in env: return env[name]
    if name in init_map: return BitVecVal(init_map[name], 32)
    return None

def process_node(node, env):
    op = node.op_type
    ins = list(node.input)
    outs = list(node.output)
    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                env[outs[0]] = BitVecVal(int(numpy_helper.to_array(attr.t).item()), 32)
        return
    if op == 'Gather':
        idx = get_val(ins[1], env)
        if idx is not None and is_bv_value(idx):
            env[outs[0]] = x[idx.as_long()]
        return
    a = get_val(ins[0], env) if len(ins) > 0 else None
    b = get_val(ins[1], env) if len(ins) > 1 else None
    if a is None: return
    if op == 'Add' and b is not None: env[outs[0]] = a + b
    elif op == 'Sub' and b is not None: env[outs[0]] = a - b
    elif op == 'Mul' and b is not None: env[outs[0]] = a * b
    elif op == 'BitwiseAnd' and b is not None: env[outs[0]] = a & b
    elif op == 'BitwiseOr' and b is not None: env[outs[0]] = a | b
    elif op == 'BitwiseXor' and b is not None: env[outs[0]] = a ^ b
    elif op == 'Less' and b is not None: env[outs[0]] = a < b
    elif op == 'Greater' and b is not None: env[outs[0]] = a > b
    elif op == 'Not': env[outs[0]] = Not(a)
    elif op == 'Equal' and b is not None: env[outs[0]] = a == b

def extract_subgraph_conditions(sg, parent_env):
    env = dict(parent_env)
    conditions = []
    for node in sg.node:
        if node.op_type == 'If':
            cond = get_val(node.input[0], env)
            if cond is not None: conditions.append(cond)
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    conditions.extend(extract_subgraph_conditions(attr.g, env))
        else:
            process_node(node, env)
    return conditions

# Extract all blocks
env = {}
all_blocks = []
for node in graph.node:
    if node.op_type in ('Cast', 'Reshape', 'Concat', 'ReduceSum'): continue
    if node.op_type == 'If':
        cond = get_val(node.input[0], env)
        block_conds = []
        if cond is not None: block_conds.append(cond)
        for attr in node.attribute:
            if attr.name == 'then_branch':
                block_conds.extend(extract_subgraph_conditions(attr.g, env))
        all_blocks.append(block_conds)
    else:
        process_node(node, env)

print(f"Extracted {len(all_blocks)} blocks, {sum(len(b) for b in all_blocks)} conditions")

# Find individually UNSAT blocks
unsat_set = set()
for i, block in enumerate(all_blocks):
    si = Solver()
    for j in range(56): si.add(x[j] >= 0, x[j] <= 255)
    for c in block: si.add(c)
    if si.check() != sat:
        unsat_set.add(i)

print(f"Individually UNSAT: {len(unsat_set)} blocks")

# Solve only satisfiable blocks
solver = Solver()
for i in range(56):
    solver.add(x[i] >= 0, x[i] <= 255)

sat_block_count = 0
for i, block in enumerate(all_blocks):
    if i in unsat_set:
        continue
    for c in block:
        solver.add(c)
    sat_block_count += 1

print(f"Added {sat_block_count} satisfiable blocks")
print("Solving...")
start = time.time()
solver.set('timeout', 120000)  # 2 min
result = solver.check()
elapsed = time.time() - start
print(f"Result: {result} ({elapsed:.1f}s)")

if result == sat:
    m = solver.model()
    flag_bytes = [m.evaluate(x[i]).as_long() for i in range(56)]
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in flag_bytes)
    print(f"\nZ3 solution: {flag}")
    print(f"Bytes: {flag_bytes}")

    # Verify with ONNX
    import onnxruntime as ort
    sess = ort.InferenceSession(MODEL_PATH)
    arr = np.array(flag_bytes, dtype=np.uint8)
    score = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: arr})[0])
    print(f"Score: {score}/2563")

    # Now hill climb from this starting point
    print("\nHill climbing from Z3 solution...")
    best = np.array(flag_bytes, dtype=np.uint8)
    best_score = score
    for iteration in range(5):
        improved = False
        for pos in range(56):
            old = int(best[pos])
            best_local = old
            best_s = best_score
            for v in range(256):
                if v == old: continue
                best[pos] = v
                s = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: best})[0])
                if s > best_s:
                    best_s = s
                    best_local = v
            best[pos] = best_local
            if best_s > best_score:
                best_score = best_s
                improved = True
        flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
        print(f"  Iteration {iteration}: score={best_score}/2563 flag='{flag}'")
        if not improved:
            break

    print(f"\nFinal score: {best_score}/2563")
    print(f"Final flag: {flag}")
    if best_score == 2563:
        print("*** PERFECT SCORE ***")
elif result == unknown:
    print("Timeout - try with fewer constraints")
else:
    print("UNSAT even with only satisfiable blocks - encoding bug")
