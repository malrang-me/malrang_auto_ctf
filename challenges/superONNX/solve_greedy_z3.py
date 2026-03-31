#!/usr/bin/env python3
"""Greedy Z3: add blocks sorted by weight (highest first), skip UNSAT."""

import onnx
import numpy as np
from z3 import *
import sys, time

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

def get_leaf_weight(if_node):
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            for n in attr.g.node:
                if n.op_type == 'If':
                    return get_leaf_weight(n)
            for n in attr.g.node:
                if n.op_type == 'Constant':
                    for a in n.attribute:
                        if a.name == 'value':
                            val = onnx.numpy_helper.to_array(a.t)
                            if n.output[0] in [o.name for o in attr.g.output]:
                                return int(val)
    return 0

UNSAT_BLOCKS = {5, 11, 25, 33, 35, 36, 52, 53, 56, 72, 77, 88, 97, 131, 132, 136, 158, 184, 192, 219, 224, 230, 235, 244, 246, 254, 259, 260, 274, 277, 298, 305, 345, 354, 359, 378, 381, 411, 413, 421, 425}

print("Extracting constraints...", flush=True)
env = {}
all_blocks = []
bi = 0
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            weight = get_leaf_weight(node)
            all_blocks.append((bi, constraints, weight))
        except:
            all_blocks.append((bi, [], 0))
        bi += 1
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

print(f"Extracted {len(all_blocks)} blocks", flush=True)

# Filter and sort by weight descending
sat_blocks = [(bi, cs, w) for bi, cs, w in all_blocks 
              if bi not in UNSAT_BLOCKS and cs and w > 0]
sat_blocks.sort(key=lambda x: -x[2])

print(f"SAT blocks to try: {len(sat_blocks)}", flush=True)

# Greedy: add highest-weight blocks first
s = Solver()
s.set("timeout", 10000)  # 10s per check
for i in range(56):
    s.add(inp[i] >= 32, inp[i] <= 126)

total_weight = 0
included = 0
skipped = 0
skipped_weights = []
start = time.time()

for bi, constraints, weight in sat_blocks:
    s.push()
    for c in constraints:
        s.add(c)
    r = s.check()
    if r == sat:
        included += 1
        total_weight += weight
    else:
        s.pop()
        skipped += 1
        skipped_weights.append(weight)
    
    if included % 50 == 0 and included > 0:
        print(f"  [{time.time()-start:.1f}s] included={included}, skipped={skipped}, weight={total_weight}", flush=True)

print(f"\nFinal: included={included}, skipped={skipped}, total_weight={total_weight}", flush=True)
print(f"Skipped weights: {sorted(skipped_weights, reverse=True)}", flush=True)

r = s.check()
print(f"Final SAT check: {r}", flush=True)
if r == sat:
    m = s.model()
    flag_bytes = [m[inp[i]].as_long() if m[inp[i]] is not None else 63 for i in range(56)]
    flag = ''.join(chr(b) for b in flag_bytes)
    print(f"FLAG: {flag}", flush=True)
    print(f"Score: {total_weight}", flush=True)
