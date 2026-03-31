#!/usr/bin/env python3
"""
Z3 solver for superONNX - v2 with proper constraint extraction.
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

# Z3 variables: 56 input bytes as BitVec(32) (since Cast uint8->int32)
inp = [BitVec(f'x{i}', 32) for i in range(56)]

def eval_subgraph(sg, parent_env):
    """Evaluate a subgraph, returning (conditions_list, env)."""
    env = dict(parent_env)
    conditions = []

    for node in sg.node:
        op = node.op_type
        ins = list(node.input)
        outs = list(node.output)

        if op == 'Constant':
            for attr in node.attribute:
                if attr.name == 'value':
                    val = int(numpy_helper.to_array(attr.t).item())
                    env[outs[0]] = BitVecVal(val, 32)

        elif op == 'Gather':
            idx = env.get(ins[1])
            if idx is not None and is_bv_value(idx):
                env[outs[0]] = inp[idx.as_long()]

        elif op == 'Add':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a + b

        elif op == 'Sub':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a - b

        elif op == 'Mul':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a * b

        elif op == 'BitwiseAnd':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a & b

        elif op == 'BitwiseOr':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a | b

        elif op == 'BitwiseXor':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a ^ b

        elif op == 'Less':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a < b  # signed

        elif op == 'Greater':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a > b  # signed

        elif op == 'Not':
            a = env.get(ins[0])
            if a is not None:
                env[outs[0]] = Not(a)

        elif op == 'Equal':
            a, b = env.get(ins[0]), env.get(ins[1])
            if a is not None and b is not None:
                env[outs[0]] = a == b

        elif op == 'If':
            cond = env.get(ins[0])
            if cond is not None:
                conditions.append(cond)

            # Recurse into then-branch
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    sub_conds, _ = eval_subgraph(attr.g, env)
                    conditions.extend(sub_conds)

    return conditions, env

# Process main graph
print("Extracting constraints...")
start = time.time()

env = {}
all_block_constraints = []

for node in graph.node:
    op = node.op_type
    ins = list(node.input)
    outs = list(node.output)

    if op == 'Cast':
        env['input_i32'] = 'INPUT_MARKER'
        continue

    if op in ('Reshape', 'Concat', 'ReduceSum'):
        continue

    if op == 'If':
        cond = env.get(ins[0])
        block_conds = []
        if cond is not None:
            block_conds.append(cond)

        for attr in node.attribute:
            if attr.name == 'then_branch':
                sub_conds, _ = eval_subgraph(attr.g, env)
                block_conds.extend(sub_conds)

        all_block_constraints.append(block_conds)
        continue

    # Regular node in main graph
    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = int(numpy_helper.to_array(attr.t).item())
                env[outs[0]] = BitVecVal(val, 32)

    elif op == 'Gather':
        idx = env.get(ins[1])
        if idx is not None and is_bv_value(idx):
            env[outs[0]] = inp[idx.as_long()]

    elif op == 'Add':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a + b

    elif op == 'Sub':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a - b

    elif op == 'Mul':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a * b

    elif op == 'BitwiseAnd':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a & b

    elif op == 'BitwiseOr':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a | b

    elif op == 'BitwiseXor':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a ^ b

    elif op == 'Less':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a < b

    elif op == 'Greater':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a > b

    elif op == 'Not':
        a = env.get(ins[0])
        if a is not None:
            env[outs[0]] = Not(a)

    elif op == 'Equal':
        a, b = env.get(ins[0]), env.get(ins[1])
        if a is not None and b is not None:
            env[outs[0]] = a == b

elapsed = time.time() - start
print(f"Extracted {len(all_block_constraints)} blocks in {elapsed:.1f}s")

# Count constraints and check for None
total_conds = 0
none_count = 0
for i, block in enumerate(all_block_constraints):
    for c in block:
        if c is None:
            none_count += 1
        else:
            total_conds += 1

print(f"Total conditions: {total_conds}, None: {none_count}")
print(f"Conditions per block (first 20): {[len(b) for b in all_block_constraints[:20]]}")

# Debug: test block 0 alone
print("\n=== DEBUG: Testing block 0 alone ===")
s0 = Solver()
for i in range(56):
    s0.add(inp[i] >= 0, inp[i] <= 255)
for c in all_block_constraints[0]:
    if c is not None:
        print(f"  Adding constraint: {c}")
        s0.add(c)
r = s0.check()
print(f"Block 0 alone: {r}")
if r == sat:
    m = s0.model()
    vals = [m.evaluate(inp[i]).as_long() for i in range(56)]
    print(f"  Solution (first 10): {vals[:10]}")

# Test blocks individually
print("\n=== Testing each block independently ===")
unsat_blocks = []
for i, block in enumerate(all_block_constraints):
    si = Solver()
    for j in range(56):
        si.add(inp[j] >= 0, inp[j] <= 255)
    for c in block:
        if c is not None:
            si.add(c)
    r = si.check()
    if r != sat:
        unsat_blocks.append(i)

print(f"Individually UNSAT blocks: {len(unsat_blocks)}")
if unsat_blocks:
    print(f"  Blocks: {unsat_blocks[:20]}")

# Try adding all constraints
print("\n=== Solving all constraints ===")
solver = Solver()
for i in range(56):
    solver.add(inp[i] >= 0, inp[i] <= 255)

for block in all_block_constraints:
    for c in block:
        if c is not None:
            solver.add(c)

start = time.time()
result = solver.check()
print(f"Result: {result} ({time.time()-start:.1f}s)")

if result == sat:
    m = solver.model()
    flag_bytes = [m.evaluate(inp[i]).as_long() for i in range(56)]
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in flag_bytes)
    print(f"\n*** FLAG: {flag} ***")

    # Verify
    import onnxruntime as ort
    sess = ort.InferenceSession(MODEL_PATH)
    arr = np.array(flag_bytes, dtype=np.uint8)
    score = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: arr})[0])
    print(f"Score: {score}/2563")
