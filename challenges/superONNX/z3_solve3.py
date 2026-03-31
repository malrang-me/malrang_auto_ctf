#!/usr/bin/env python3
"""
Z3 solver for superONNX - v3: fix initializer loading bug.
"""
import onnx
from onnx import numpy_helper
from z3 import *
import numpy as np
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Build initializer lookup
init_map = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_map[init.name] = int(arr.item())

# Z3 variables: 56 input bytes as BitVec(32)
x = [BitVec(f'x{i}', 32) for i in range(56)]

def get_val(name, env):
    """Resolve a name from env, init_map, or return None."""
    if name in env:
        return env[name]
    if name in init_map:
        return BitVecVal(init_map[name], 32)
    return None

def process_node(node, env):
    """Process a single node, updating env."""
    op = node.op_type
    ins = list(node.input)
    outs = list(node.output)

    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = int(numpy_helper.to_array(attr.t).item())
                env[outs[0]] = BitVecVal(val, 32)
        return

    if op == 'Gather':
        idx = get_val(ins[1], env)
        if idx is not None and is_bv_value(idx):
            env[outs[0]] = x[idx.as_long()]
        return

    a = get_val(ins[0], env) if len(ins) > 0 else None
    b = get_val(ins[1], env) if len(ins) > 1 else None

    if op == 'Add' and a is not None and b is not None:
        env[outs[0]] = a + b
    elif op == 'Sub' and a is not None and b is not None:
        env[outs[0]] = a - b
    elif op == 'Mul' and a is not None and b is not None:
        env[outs[0]] = a * b
    elif op == 'BitwiseAnd' and a is not None and b is not None:
        env[outs[0]] = a & b
    elif op == 'BitwiseOr' and a is not None and b is not None:
        env[outs[0]] = a | b
    elif op == 'BitwiseXor' and a is not None and b is not None:
        env[outs[0]] = a ^ b
    elif op == 'Less' and a is not None and b is not None:
        env[outs[0]] = a < b
    elif op == 'Greater' and a is not None and b is not None:
        env[outs[0]] = a > b
    elif op == 'Not' and a is not None:
        env[outs[0]] = Not(a)
    elif op == 'Equal' and a is not None and b is not None:
        env[outs[0]] = a == b

def extract_subgraph_conditions(sg, parent_env):
    """Extract all If conditions from a subgraph recursively."""
    env = dict(parent_env)
    conditions = []

    for node in sg.node:
        if node.op_type == 'If':
            cond = get_val(node.input[0], env)
            if cond is not None:
                conditions.append(cond)
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    sub_conds = extract_subgraph_conditions(attr.g, env)
                    conditions.extend(sub_conds)
        else:
            process_node(node, env)

    return conditions

# Process main graph
print("Extracting constraints from ONNX graph...")
start = time.time()

env = {}
all_blocks = []

for node in graph.node:
    if node.op_type == 'Cast':
        continue
    if node.op_type in ('Reshape', 'Concat', 'ReduceSum'):
        continue

    if node.op_type == 'If':
        cond = get_val(node.input[0], env)
        block_conds = []
        if cond is not None:
            block_conds.append(cond)
        for attr in node.attribute:
            if attr.name == 'then_branch':
                sub_conds = extract_subgraph_conditions(attr.g, env)
                block_conds.extend(sub_conds)
        all_blocks.append(block_conds)
    else:
        process_node(node, env)

elapsed = time.time() - start
print(f"Extracted {len(all_blocks)} blocks in {elapsed:.1f}s")
print(f"Conditions per block (first 20): {[len(b) for b in all_blocks[:20]]}")
total_conds = sum(len(b) for b in all_blocks)
print(f"Total conditions: {total_conds}")

# Debug: check individually UNSAT blocks
print("\nChecking for individually UNSAT blocks...")
unsat_blocks = []
for i, block in enumerate(all_blocks):
    si = Solver()
    for j in range(56):
        si.add(x[j] >= 0, x[j] <= 255)
    for c in block:
        si.add(c)
    if si.check() != sat:
        unsat_blocks.append(i)

if unsat_blocks:
    print(f"WARNING: {len(unsat_blocks)} individually UNSAT blocks: {unsat_blocks[:10]}")
    # Debug first UNSAT block
    bi = unsat_blocks[0]
    print(f"  Block {bi} conditions:")
    for c in all_blocks[bi]:
        print(f"    {c}")
else:
    print("All blocks individually SAT")

# Solve ALL constraints
print("\nSolving all constraints with Z3...")
solver = Solver()
for i in range(56):
    solver.add(x[i] >= 0, x[i] <= 255)

for block in all_blocks:
    for c in block:
        solver.add(c)

start = time.time()
result = solver.check()
elapsed = time.time() - start
print(f"Result: {result} ({elapsed:.1f}s)")

if result == sat:
    m = solver.model()
    flag_bytes = [m.evaluate(x[i]).as_long() for i in range(56)]
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in flag_bytes)
    print(f"\n*** FLAG: {flag} ***")

    # Verify
    import onnxruntime as ort
    sess = ort.InferenceSession(MODEL_PATH)
    arr = np.array(flag_bytes, dtype=np.uint8)
    score = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: arr})[0])
    print(f"Score: {score}/2563")

    if score == 2563:
        print("\n=== PERFECT SCORE - FLAG VERIFIED ===")
    else:
        print(f"\nNot perfect. Missing {2563-score} points.")
else:
    print("UNSAT - trying incremental approach...")
    # Try to find max satisfiable subset
    solver2 = Optimize()
    for i in range(56):
        solver2.add(x[i] >= 0, x[i] <= 255)

    block_vars = []
    for i, block in enumerate(all_blocks):
        bv = Bool(f'block_{i}')
        block_vars.append(bv)
        solver2.add(Implies(bv, And(*block)))

    # Maximize number of satisfied blocks
    solver2.maximize(Sum([If(bv, 1, 0) for bv in block_vars]))

    print("Running Optimize (maximize satisfied blocks)...")
    start = time.time()
    result = solver2.check()
    print(f"Optimize result: {result} ({time.time()-start:.1f}s)")

    if result == sat:
        m = solver2.model()
        sat_count = sum(1 for bv in block_vars if is_true(m.evaluate(bv)))
        print(f"Satisfied blocks: {sat_count}/{len(all_blocks)}")
        flag_bytes = [m.evaluate(x[i]).as_long() for i in range(56)]
        flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in flag_bytes)
        print(f"Best candidate: {flag}")

        # Verify
        import onnxruntime as ort
        sess = ort.InferenceSession(MODEL_PATH)
        arr = np.array(flag_bytes, dtype=np.uint8)
        score = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: arr})[0])
        print(f"Score: {score}/2563")
