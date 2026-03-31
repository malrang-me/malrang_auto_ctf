#!/usr/bin/env python3
"""Solve superONNX: Use Z3 Optimize to maximize score."""

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
    ops = {
        'Add': lambda: a + b, 'Sub': lambda: a - b, 'Mul': lambda: a * b,
        'BitwiseAnd': lambda: a & b, 'BitwiseOr': lambda: a | b, 'BitwiseXor': lambda: a ^ b,
        'Less': lambda: a < b, 'Greater': lambda: a > b,
    }
    if op in ops:
        env[node.output[0]] = ops[op]()
    else:
        raise ValueError(f"Unknown op: {op}")

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

# Extract all blocks
env = {}
all_blocks = []  # (constraints_list, weight)
for node in graph.node:
    if node.op_type == 'If':
        try:
            constraints = extract_constraints(node, env)
            weight = get_leaf_weight(node)
            all_blocks.append((constraints, weight))
        except Exception as e:
            print(f"Error block {len(all_blocks)}: {e}")
            all_blocks.append(([], 0))
    elif node.op_type not in ('Concat', 'ReduceSum', 'Reshape'):
        eval_node(node, env)

print(f"Extracted {len(all_blocks)} blocks, total max weight = {sum(w for _, w in all_blocks)}")

# Use Z3 Optimize to maximize the weighted score
opt = Optimize()

# Input byte constraints
for i in range(56):
    opt.add(inp[i] >= 32, inp[i] <= 126)

# For each block: create an indicator var, score = If(all_constraints, weight, 0)
total_score = BitVecVal(0, 32)
for bi, (constraints, weight) in enumerate(all_blocks):
    if not constraints:
        continue
    # All constraints must be true for this block
    block_sat = And(*constraints) if len(constraints) > 1 else constraints[0]
    block_score = If(block_sat, BitVecVal(weight, 32), BitVecVal(0, 32))
    total_score = total_score + block_score

opt.maximize(total_score)

print("Solving (this may take a while)...")
result = opt.check()
print(f"Result: {result}")

if result == sat:
    m = opt.model()
    flag_bytes = []
    for i in range(56):
        val = m[inp[i]]
        if val is not None:
            flag_bytes.append(val.as_long())
        else:
            flag_bytes.append(ord('?'))
    flag = ''.join(chr(b) for b in flag_bytes)
    
    # Compute score
    score = 0
    subst_pairs = [(inp[i], BitVecVal(flag_bytes[i], 32)) for i in range(56)]
    for bi, (constraints, weight) in enumerate(all_blocks):
        if not constraints:
            continue
        all_true = True
        for c in constraints:
            c_sub = simplify(substitute(c, *subst_pairs))
            if not is_true(c_sub):
                all_true = False
                break
        if all_true:
            score += weight
    
    print(f"Computed score: {score}")
    print(f"FLAG: {flag}")
else:
    print("Optimization failed!")
