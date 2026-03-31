#!/usr/bin/env python3
"""Carefully test: solve blocks 0-10 with Z3, verify with Python evaluator."""

import onnx
import numpy as np
from z3 import *

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_vals = {}
for init in graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    init_vals[init.name] = int(arr) if arr.ndim == 0 else arr

inp = [BitVec(f'x{i}', 32) for i in range(56)]

def resolve_val(name, env):
    if name in env: return env[name]
    if name in init_vals:
        v = init_vals[name]
        return BitVecVal(int(v), 32) if isinstance(v, (int, np.integer)) else v
    raise ValueError(f"Cannot resolve: {name}")

def eval_node(node, env):
    op = node.op_type
    if op == 'Cast': env[node.output[0]] = 'INPUT'; return
    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                env[node.output[0]] = int(onnx.numpy_helper.to_array(attr.t))
        return
    if op == 'Gather':
        idx = env.get(node.input[1], init_vals.get(node.input[1]))
        env[node.output[0]] = inp[int(idx)]
        return
    if op == 'Not':
        env[node.output[0]] = Not(resolve_val(node.input[0], env))
        return
    if op == 'Reshape': env[node.output[0]] = env.get(node.input[0]); return
    if len(node.input) < 2: return
    a = resolve_val(node.input[0], env)
    b = resolve_val(node.input[1], env)
    if isinstance(a, int): a = BitVecVal(a, 32)
    if isinstance(b, int): b = BitVecVal(b, 32)
    m = {'Add': a+b, 'Sub': a-b, 'Mul': a*b, 'BitwiseAnd': a&b,
         'BitwiseOr': a|b, 'BitwiseXor': a^b, 'Less': a<b, 'Greater': a>b}
    if op in m: env[node.output[0]] = m[op]

def extract_constraints(if_node, env):
    constraints = []
    cond = resolve_val(if_node.input[0], env)
    constraints.append(cond)
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            then_env = dict(env)
            for n in attr.g.node:
                if n.op_type == 'If':
                    constraints.extend(extract_constraints(n, then_env))
                else:
                    eval_node(n, then_env)
    return constraints

# Extract first 20 blocks
env = {}
blocks = []
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            blocks.append(constraints)
        except Exception as e:
            blocks.append([])
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

# Try solving blocks 0-9
s = Solver()
for i in range(56):
    s.add(inp[i] >= 32, inp[i] <= 126)

for bi in range(min(20, len(blocks))):
    for c in blocks[bi]:
        s.add(c)
    r = s.check()
    if r != sat:
        print(f"UNSAT after adding block {bi}!")
        # Try without this block
        s2 = Solver()
        for i in range(56):
            s2.add(inp[i] >= 32, inp[i] <= 126)
        for c in blocks[bi]:
            s2.add(c)
        r2 = s2.check()
        print(f"  Block {bi} alone: {r2}")
        if r2 == sat:
            m2 = s2.model()
            vals = [m2[inp[i]].as_long() if m2[inp[i]] is not None else 63 for i in range(56)]
            print(f"  Block {bi} alone solution: {''.join(chr(v) for v in vals)}")
        break
    else:
        m = s.model()
        vals = [m[inp[i]].as_long() if m[inp[i]] is not None else 63 for i in range(56)]
        print(f"Blocks 0-{bi} SAT: {''.join(chr(v) for v in vals)}")

# Also try: solve ALL 440 blocks but with wider range (0-255 instead of 32-126)
print("\n=== Trying with full byte range 0-255 ===")
s3 = Solver()
for i in range(56):
    s3.add(inp[i] >= 0, inp[i] <= 255)

for block in blocks:
    for c in block:
        s3.add(c)

r3 = s3.check()
print(f"All 440 blocks with 0-255 range: {r3}")
if r3 == sat:
    m3 = s3.model()
    vals = [m3[inp[i]].as_long() if m3[inp[i]] is not None else 0 for i in range(56)]
    print(f"Solution (hex): {bytes(vals).hex()}")
    print(f"Solution (str): {''.join(chr(v) if 32<=v<=126 else '.' for v in vals)}")
