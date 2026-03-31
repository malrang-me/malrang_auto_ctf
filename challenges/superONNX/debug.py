#!/usr/bin/env python3
"""Debug: print first few blocks' constraints."""

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
    if name == 'input_i32':
        return inp
    raise ValueError(f"Cannot resolve: {name}")

def eval_node(node, env):
    op = node.op_type
    if op == 'Cast':
        env[node.output[0]] = env.get(node.input[0], inp)
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
        raise ValueError(f"Unhandled unary: {op}")
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

def extract_constraints(if_node, env, depth=0):
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
            inner = extract_constraints(n, then_env, depth+1)
            constraints.extend(inner)
        else:
            eval_node(n, then_env)
    
    return constraints

# Process and print first 3 blocks
env = {}
block_id = 0
for node in graph.node:
    if node.op_type == 'If':
        if block_id < 5:
            constraints = extract_constraints(node, env)
            print(f"\n=== Block {block_id} ({len(constraints)} constraints) ===")
            for i, c in enumerate(constraints):
                print(f"  C{i}: {c}")
        block_id += 1
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

# Test: can we satisfy just block 0?
print("\n=== TEST: Block 0 alone ===")
env2 = {}
block_id2 = 0
for node in graph.node:
    if node.op_type == 'If':
        if block_id2 == 0:
            constraints = extract_constraints(node, env2)
            s = Solver()
            for i in range(56):
                s.add(inp[i] >= 32, inp[i] <= 126)
            for c in constraints:
                s.add(c)
            print(f"Checking {len(constraints)} constraints...")
            r = s.check()
            print(f"Result: {r}")
            if r == sat:
                m = s.model()
                vals = [m[inp[i]].as_long() if m[inp[i]] is not None else 63 for i in range(56)]
                print(f"Sample: {''.join(chr(v) for v in vals)}")
        block_id2 += 1
        break
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env2)
