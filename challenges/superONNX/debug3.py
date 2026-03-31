#!/usr/bin/env python3
"""Debug: verify Z3 constraints against ONNX runtime for all A's input."""
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
    if name in env:
        return env[name]
    if name in init_vals:
        v = init_vals[name]
        return BitVecVal(int(v), 32) if isinstance(v, (int, np.integer)) else v
    raise ValueError(f"Cannot resolve: {name}")

def eval_node(node, env):
    op = node.op_type
    if op == 'Cast':
        env[node.output[0]] = 'INPUT_ARRAY'
        return
    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = onnx.numpy_helper.to_array(attr.t)
                env[node.output[0]] = int(val) if val.ndim == 0 else val
        return
    if op == 'Gather':
        idx = env.get(node.input[1], init_vals.get(node.input[1]))
        idx = int(idx) if not isinstance(idx, int) else idx
        env[node.output[0]] = inp[idx]
        return
    if op == 'Not':
        a = resolve_val(node.input[0], env)
        env[node.output[0]] = Not(a)
        return
    if op == 'Reshape':
        env[node.output[0]] = env.get(node.input[0])
        return
    if len(node.input) < 2:
        raise ValueError(f"Unhandled: {op}")
    a = resolve_val(node.input[0], env)
    b = resolve_val(node.input[1], env)
    if isinstance(a, int): a = BitVecVal(a, 32)
    if isinstance(b, int): b = BitVecVal(b, 32)
    if op == 'Add': env[node.output[0]] = a + b
    elif op == 'Sub': env[node.output[0]] = a - b
    elif op == 'Mul': env[node.output[0]] = a * b
    elif op == 'BitwiseAnd': env[node.output[0]] = a & b
    elif op == 'BitwiseOr': env[node.output[0]] = a | b
    elif op == 'BitwiseXor': env[node.output[0]] = a ^ b
    elif op == 'Less': env[node.output[0]] = a < b
    elif op == 'Greater': env[node.output[0]] = a > b

def extract_constraints(if_node, env):
    constraints = []
    cond = resolve_val(if_node.input[0], env)
    constraints.append(cond)
    then_graph = None
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            then_graph = attr.g
            break
    if then_graph is None:
        return constraints
    then_env = dict(env)
    for n in then_graph.node:
        if n.op_type == 'If':
            inner = extract_constraints(n, then_env)
            constraints.extend(inner)
        else:
            eval_node(n, then_env)
    return constraints

# Extract all block constraints
env = {}
all_blocks = []
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            all_blocks.append(constraints)
        except Exception as e:
            all_blocks.append([])
            print(f"Error block {len(all_blocks)-1}: {e}")
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

print(f"Total blocks: {len(all_blocks)}")

# Now substitute all A's (65) and check which blocks are satisfied
test_input = [65] * 56
subst = [(inp[i], BitVecVal(test_input[i], 32)) for i in range(56)]

sat_count = 0
unsat_count = 0
for bi, block in enumerate(all_blocks):
    s = Solver()
    for c in block:
        c_sub = substitute(c, *subst)
        s.add(c_sub)
    r = s.check()
    if r == sat:
        sat_count += 1
    else:
        unsat_count += 1
        if unsat_count <= 10:
            print(f"Block {bi} UNSAT for all A's. Constraints:")
            for ci, c in enumerate(block):
                c_sub = substitute(c, *subst)
                print(f"  C{ci}: {simplify(c_sub)}")

print(f"\nAll A's: {sat_count} blocks SAT, {unsat_count} blocks UNSAT")
print(f"Expected ONNX score should be related to {sat_count} SAT blocks")
