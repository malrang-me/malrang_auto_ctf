#!/usr/bin/env python3
"""Optimized solver: compile scorer + per-byte exhaustive + crossover."""

import onnx
import numpy as np
import random
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_vals = {}
for init in graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    init_vals[init.name] = int(arr) if arr.ndim == 0 else arr

def get_const_val(node):
    for attr in node.attribute:
        if attr.name == 'value':
            return int(onnx.numpy_helper.to_array(attr.t))
    return None

def to_i32_str(e):
    return f"(({e}) + 2147483648 & 4294967295) - 2147483648"

# Compile blocks to Python expressions
env = {}
blocks_info = []  # (condition_strs, weight)

def compile_nodes_to_str(nodes, cur_env):
    """Compile nodes, return list of condition strings for If nodes."""
    conds = []
    for n in nodes:
        op = n.op_type
        if op == 'Constant':
            cur_env[n.output[0]] = str(get_const_val(n))
            continue
        if op == 'Gather':
            idx = cur_env.get(n.input[1], str(init_vals.get(n.input[1], 0)))
            cur_env[n.output[0]] = f'x[{idx}]'
            continue
        if op == 'Not':
            a = cur_env[n.input[0]]
            cur_env[n.output[0]] = f'(not ({a}))'
            continue
        if op == 'If':
            conds.append(cur_env[n.input[0]])
            for attr in n.attribute:
                if attr.name == 'then_branch':
                    inner = compile_nodes_to_str(list(attr.g.node), dict(cur_env))
                    conds.extend(inner)
            return conds
        if len(n.input) < 2:
            continue
        a = cur_env.get(n.input[0])
        if a is None:
            v = init_vals.get(n.input[0])
            a = str(int(v)) if v is not None else '0'
        b = cur_env.get(n.input[1])
        if b is None:
            v = init_vals.get(n.input[1])
            b = str(int(v)) if v is not None else '0'
        ops = {
            'Add': f'(({a})+({b}))', 'Sub': f'(({a})-({b}))', 'Mul': f'(({a})*({b}))',
            'BitwiseAnd': f'(({a})&({b}))', 'BitwiseOr': f'(({a})|({b}))', 'BitwiseXor': f'(({a})^({b}))',
            'Less': f'({to_i32_str(a)}<{to_i32_str(b)})', 'Greater': f'({to_i32_str(a)}>{to_i32_str(b)})',
        }
        if op in ops:
            cur_env[n.output[0]] = ops[op]
    return conds

def get_weight_from_if(if_node, cur_env):
    conds = [cur_env[if_node.input[0]]]
    weight = 0
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            then_env = dict(cur_env)
            for n in attr.g.node:
                if n.op_type == 'If':
                    inner_c, inner_w = get_weight_from_if(n, then_env)
                    conds.extend(inner_c)
                    weight = inner_w
                elif n.op_type == 'Constant':
                    val = get_const_val(n)
                    then_env[n.output[0]] = str(val)
                    if n.output[0] in [o.name for o in attr.g.output]:
                        weight = val
                elif n.op_type == 'Gather':
                    idx = then_env.get(n.input[1], str(init_vals.get(n.input[1], 0)))
                    then_env[n.output[0]] = f'x[{idx}]'
                elif n.op_type == 'Not':
                    then_env[n.output[0]] = f'(not ({then_env[n.input[0]]}))'
                elif len(n.input) >= 2:
                    a = then_env.get(n.input[0])
                    if a is None: a = str(int(init_vals.get(n.input[0], 0)))
                    b = then_env.get(n.input[1])
                    if b is None: b = str(int(init_vals.get(n.input[1], 0)))
                    ops = {
                        'Add': f'(({a})+({b}))', 'Sub': f'(({a})-({b}))', 'Mul': f'(({a})*({b}))',
                        'BitwiseAnd': f'(({a})&({b}))', 'BitwiseOr': f'(({a})|({b}))', 'BitwiseXor': f'(({a})^({b}))',
                        'Less': f'({to_i32_str(a)}<{to_i32_str(b)})', 'Greater': f'({to_i32_str(a)}>{to_i32_str(b)})',
                    }
                    if n.op_type in ops:
                        then_env[n.output[0]] = ops[n.op_type]
    return conds, weight

for node in graph.node:
    op = node.op_type
    if op == 'Cast': continue
    if op in ('Reshape', 'Concat', 'ReduceSum'): continue
    if op == 'If':
        conds, weight = get_weight_from_if(node, env)
        blocks_info.append((conds, weight))
        continue
    if op == 'Constant':
        env[node.output[0]] = str(get_const_val(node))
        continue
    if op == 'Gather':
        idx = env.get(node.input[1], str(init_vals.get(node.input[1], 0)))
        env[node.output[0]] = f'x[{idx}]'
        continue
    if op == 'Not':
        env[node.output[0]] = f'(not ({env[node.input[0]]}))'
        continue
    if len(node.input) < 2: continue
    a = env.get(node.input[0])
    if a is None: a = str(int(init_vals.get(node.input[0], 0)))
    b = env.get(node.input[1])
    if b is None: b = str(int(init_vals.get(node.input[1], 0)))
    ops = {
        'Add': f'(({a})+({b}))', 'Sub': f'(({a})-({b}))', 'Mul': f'(({a})*({b}))',
        'BitwiseAnd': f'(({a})&({b}))', 'BitwiseOr': f'(({a})|({b}))', 'BitwiseXor': f'(({a})^({b}))',
        'Less': f'({to_i32_str(a)}<{to_i32_str(b)})', 'Greater': f'({to_i32_str(a)}>{to_i32_str(b)})',
    }
    if op in ops:
        env[node.output[0]] = ops[op]

print(f"Compiled {len(blocks_info)} blocks")

# Generate fast scorer function
lines = ["def score(x):"]
lines.append("  s=0")
for bi, (conds, weight) in enumerate(blocks_info):
    if weight == 0: continue
    c = " and ".join(conds)
    lines.append(f"  if {c}: s+={weight}")
lines.append("  return s")

code = "\n".join(lines)
exec(compile(code, '<score>', 'exec'))

x_test = [65]*56
print(f"All A's: {score(x_test)}")

# Per-byte exhaustive search (greedy)
print("\nPhase 1: Per-byte exhaustive optimization...")
x = [65]*56
best_s = score(x)
improved = True
passes = 0

while improved and passes < 20:
    improved = False
    passes += 1
    for pos in range(56):
        best_val = x[pos]
        for v in range(32, 127):
            x[pos] = v
            s = score(x)
            if s > best_s:
                best_s = s
                best_val = v
                improved = True
        x[pos] = best_val
    print(f"  Pass {passes}: score={best_s} - {''.join(chr(b) for b in x)}")

print(f"\nAfter per-byte optimization: score={best_s}")
print(f"Result: {''.join(chr(b) for b in x)}")

# Phase 2: SA with 2-byte mutations from the good starting point
print("\nPhase 2: Fine-tuning with SA (2-byte mutations)...")
start = time.time()
current = x[:]
current_s = best_s
best = x[:]
best_s2 = best_s

T = 10.0
for step in range(5000000):
    if time.time() - start > 120:
        break
    
    n_mut = random.choice([1, 2])
    positions = random.sample(range(56), n_mut)
    old = [(p, current[p]) for p in positions]
    for p in positions:
        current[p] = random.randint(32, 126)
    
    ns = score(current)
    if ns > current_s or (T > 0.001 and random.random() < 2.718 ** ((ns - current_s) / T)):
        current_s = ns
        if ns > best_s2:
            best_s2 = ns
            best = current[:]
            print(f"  [{time.time()-start:.1f}s] score={best_s2} - {''.join(chr(b) for b in best)}")
    else:
        for p, v in old:
            current[p] = v
    
    T *= 0.999999

print(f"\n=== FINAL ===")
print(f"Score: {best_s2} / 2563")
print(f"Input: {''.join(chr(b) for b in best)}")

# Phase 3: Another round of per-byte from best SA result
print("\nPhase 3: Final per-byte sweep...")
x = best[:]
best_s3 = best_s2
improved = True
while improved:
    improved = False
    for pos in range(56):
        best_val = x[pos]
        for v in range(32, 127):
            x[pos] = v
            s = score(x)
            if s > best_s3:
                best_s3 = s
                best_val = v
                improved = True
        x[pos] = best_val

print(f"Final score: {best_s3} / 2563")
print(f"FLAG: {''.join(chr(b) for b in x)}")
