#!/usr/bin/env python3
"""Solve: add only individually SAT blocks and solve with Z3."""

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

# Known individually UNSAT blocks
UNSAT_BLOCKS = {5, 11, 25, 33, 35, 36, 52, 53, 56, 72, 77, 88, 97, 131, 132, 136, 158, 184, 192, 219, 224, 230, 235, 244, 246, 254, 259, 260, 274, 277, 298, 305, 345, 354, 359, 378, 381, 411, 413, 421, 425}

env = {}
blocks = []
bi = 0
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            blocks.append((bi, constraints))
        except:
            blocks.append((bi, []))
        bi += 1
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

# Filter to only SAT blocks
sat_blocks = [(bi, cs) for bi, cs in blocks if bi not in UNSAT_BLOCKS and cs]
print(f"SAT blocks to solve: {len(sat_blocks)}")

# Incremental solving - add blocks in order, skip those that cause UNSAT
s = Solver()
s.set("timeout", 300000)  # 5 min
for i in range(56):
    s.add(inp[i] >= 32, inp[i] <= 126)

included = 0
skipped = 0
for bi, constraints in sat_blocks:
    s.push()
    for c in constraints:
        s.add(c)
    r = s.check()
    if r == sat:
        included += 1
    else:
        s.pop()
        skipped += 1
        if skipped <= 20:
            print(f"Skipping block {bi} (conflicts with {included} included blocks)")

print(f"\nIncluded: {included}, Skipped: {skipped}")

r = s.check()
print(f"Final check: {r}")
if r == sat:
    m = s.model()
    flag_bytes = [m[inp[i]].as_long() if m[inp[i]] is not None else 63 for i in range(56)]
    flag = ''.join(chr(b) for b in flag_bytes)
    print(f"FLAG: {flag}")
    
    # Verify with compiled scorer
    # ... will verify separately
