#!/usr/bin/env python3
"""Find individually unsatisfiable blocks."""

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

env = {}
blocks = []
weights = []
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            weight = get_leaf_weight(node)
            blocks.append(constraints)
            weights.append(weight)
        except:
            blocks.append([])
            weights.append(0)
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

# Check each block individually (with 0-255 range for max flexibility)
unsat_blocks = []
sat_blocks = []
for bi in range(len(blocks)):
    s = Solver()
    s.set("timeout", 5000)  # 5s timeout per block
    for i in range(56):
        s.add(inp[i] >= 0, inp[i] <= 255)
    for c in blocks[bi]:
        s.add(c)
    r = s.check()
    if r == unsat:
        unsat_blocks.append(bi)
    elif r == sat:
        sat_blocks.append(bi)
    # unknown = timeout, treat as potentially sat

print(f"Individually SAT: {len(sat_blocks)}")
print(f"Individually UNSAT: {len(unsat_blocks)}")
print(f"UNSAT block weights: {[weights[b] for b in unsat_blocks]}")
print(f"Sum of UNSAT weights: {sum(weights[b] for b in unsat_blocks)}")
print(f"Sum of SAT weights: {sum(weights[b] for b in sat_blocks)}")
print(f"Max achievable score: {sum(weights[b] for b in sat_blocks)}")
print(f"UNSAT blocks: {unsat_blocks[:30]}...")

# Now check: which block pairs conflict?
# Focus on the first conflict: which individually SAT blocks conflict with each other?
