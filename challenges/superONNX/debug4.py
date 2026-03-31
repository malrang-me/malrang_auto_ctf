#!/usr/bin/env python3
"""Debug: find which blocks conflict with each other using UNSAT core."""
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
    if op == 'Cast': env[node.output[0]] = 'INPUT_ARRAY'; return
    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = onnx.numpy_helper.to_array(attr.t)
                env[node.output[0]] = int(val) if val.ndim == 0 else val
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
    m = {'Add': lambda: a+b, 'Sub': lambda: a-b, 'Mul': lambda: a*b,
         'BitwiseAnd': lambda: a&b, 'BitwiseOr': lambda: a|b, 'BitwiseXor': lambda: a^b,
         'Less': lambda: a<b, 'Greater': lambda: a>b}
    if op in m: env[node.output[0]] = m[op]()

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

env = {}
all_blocks = []
for node in graph.node:
    if node.op_type == 'If':
        try:
            all_blocks.append(extract_constraints(node, env))
        except Exception as e:
            all_blocks.append([])
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

print(f"Total blocks: {len(all_blocks)}")

# Try incremental: add blocks one by one, find first conflict
s = Solver()
for i in range(56):
    s.add(inp[i] >= 32, inp[i] <= 126)

sat_blocks = 0
for bi, block in enumerate(all_blocks):
    s.push()
    for c in block:
        s.add(c)
    r = s.check()
    if r == sat:
        sat_blocks += 1
    else:
        s.pop()
        if bi < 50:
            print(f"Block {bi} conflicts with previous {sat_blocks} blocks")

print(f"\nMaximum simultaneously satisfiable blocks (greedy): {sat_blocks}")
if sat_blocks > 0:
    m = s.model()
    flag_bytes = [m[inp[i]].as_long() if m[inp[i]] is not None else 63 for i in range(56)]
    flag = ''.join(chr(b) for b in flag_bytes)
    print(f"Greedy solution: {flag}")
