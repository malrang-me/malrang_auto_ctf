#!/usr/bin/env python3
"""Compile ONNX constraints to Python code string, exec it for speed."""

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

def to_i32_str(expr):
    return f"(({expr}) + 2147483648 & 4294967295) - 2147483648"

def compile_expr_str(nodes, env, depth=0):
    """Compile nodes to Python expression strings. Returns list of condition strings."""
    conditions = []
    for n in nodes:
        op = n.op_type
        if op == 'Constant':
            env[n.output[0]] = str(get_const_val(n))
            continue
        if op == 'Gather':
            idx_name = n.input[1]
            idx = env.get(idx_name, str(init_vals.get(idx_name, 0)))
            env[n.output[0]] = f'x[{idx}]'
            continue
        if op == 'Not':
            a = env[n.input[0]]
            env[n.output[0]] = f'(not ({a}))'
            continue
        if op == 'If':
            cond = env[n.input[0]]
            conditions.append(cond)
            for attr in n.attribute:
                if attr.name == 'then_branch':
                    inner = compile_expr_str(attr.g.node, dict(env), depth+1)
                    conditions.extend(inner)
            return conditions
        
        if len(n.input) < 2:
            continue
        
        a = env.get(n.input[0])
        if a is None:
            v = init_vals.get(n.input[0])
            a = str(int(v)) if v is not None else n.input[0]
        b = env.get(n.input[1])
        if b is None:
            v = init_vals.get(n.input[1])
            b = str(int(v)) if v is not None else n.input[1]
        
        op_map = {
            'Add': f'(({a}) + ({b}))',
            'Sub': f'(({a}) - ({b}))',
            'Mul': f'(({a}) * ({b}))',
            'BitwiseAnd': f'(({a}) & ({b}))',
            'BitwiseOr': f'(({a}) | ({b}))',
            'BitwiseXor': f'(({a}) ^ ({b}))',
            'Less': f'({to_i32_str(a)} < {to_i32_str(b)})',
            'Greater': f'({to_i32_str(a)} > {to_i32_str(b)})',
        }
        if op in op_map:
            env[n.output[0]] = op_map[op]
    
    return conditions

# Build all blocks as Python code
env = {}
blocks_code = []  # list of (conditions_code_list, weight)

for node in graph.node:
    op = node.op_type
    if op == 'Cast': continue
    if op in ('Reshape', 'Concat', 'ReduceSum'): continue
    
    if op == 'If':
        cond_str = env[node.input[0]]
        
        # Get weight by traversing then branches
        def get_weight_and_conds(if_node, cur_env):
            conds = [cur_env[if_node.input[0]]]
            for attr in if_node.attribute:
                if attr.name == 'then_branch':
                    then_env = dict(cur_env)
                    weight = 0
                    for n in attr.g.node:
                        if n.op_type == 'If':
                            inner_conds, inner_weight = get_weight_and_conds(n, then_env)
                            conds.extend(inner_conds)
                            weight = inner_weight
                        elif n.op_type == 'Constant':
                            val = get_const_val(n)
                            then_env[n.output[0]] = str(val)
                            if n.output[0] in [o.name for o in attr.g.output]:
                                weight = val
                        elif n.op_type == 'Gather':
                            idx_name = n.input[1]
                            idx = then_env.get(idx_name, str(init_vals.get(idx_name, 0)))
                            then_env[n.output[0]] = f'x[{idx}]'
                        elif n.op_type == 'Not':
                            a = then_env[n.input[0]]
                            then_env[n.output[0]] = f'(not ({a}))'
                        elif len(n.input) >= 2:
                            a = then_env.get(n.input[0])
                            if a is None:
                                v = init_vals.get(n.input[0])
                                a = str(int(v)) if v is not None else '0'
                            b = then_env.get(n.input[1])
                            if b is None:
                                v = init_vals.get(n.input[1])
                                b = str(int(v)) if v is not None else '0'
                            
                            op2 = n.op_type
                            ops = {
                                'Add': f'(({a}) + ({b}))',
                                'Sub': f'(({a}) - ({b}))',
                                'Mul': f'(({a}) * ({b}))',
                                'BitwiseAnd': f'(({a}) & ({b}))',
                                'BitwiseOr': f'(({a}) | ({b}))',
                                'BitwiseXor': f'(({a}) ^ ({b}))',
                                'Less': f'({to_i32_str(a)} < {to_i32_str(b)})',
                                'Greater': f'({to_i32_str(a)} > {to_i32_str(b)})',
                            }
                            if op2 in ops:
                                then_env[n.output[0]] = ops[op2]
                    return conds, weight
            return conds, 0
        
        conds, weight = get_weight_and_conds(node, env)
        conds[0] = cond_str  # override with actual expression
        blocks_code.append((conds, weight))
        continue
    
    # Regular node
    if op == 'Constant':
        env[node.output[0]] = str(get_const_val(node))
        continue
    if op == 'Gather':
        idx = env.get(node.input[1], str(init_vals.get(node.input[1], 0)))
        env[node.output[0]] = f'x[{idx}]'
        continue
    if op == 'Not':
        a = env[node.input[0]]
        env[node.output[0]] = f'(not ({a}))'
        continue
    if len(node.input) < 2:
        continue
    a = env.get(node.input[0])
    if a is None:
        v = init_vals.get(node.input[0])
        a = str(int(v)) if v is not None else '0'
    b = env.get(node.input[1])
    if b is None:
        v = init_vals.get(node.input[1])
        b = str(int(v)) if v is not None else '0'
    
    ops = {
        'Add': f'(({a}) + ({b}))',
        'Sub': f'(({a}) - ({b}))',
        'Mul': f'(({a}) * ({b}))',
        'BitwiseAnd': f'(({a}) & ({b}))',
        'BitwiseOr': f'(({a}) | ({b}))',
        'BitwiseXor': f'(({a}) ^ ({b}))',
        'Less': f'({to_i32_str(a)} < {to_i32_str(b)})',
        'Greater': f'({to_i32_str(a)} > {to_i32_str(b)})',
    }
    if op in ops:
        env[node.output[0]] = ops[op]

print(f"Compiled {len(blocks_code)} blocks")

# Generate a Python function
func_lines = ["def score(x):"]
func_lines.append("  s = 0")
for bi, (conds, weight) in enumerate(blocks_code):
    if weight == 0:
        continue
    # Chain conditions with short-circuit
    cond_combined = " and ".join(conds)
    func_lines.append(f"  if {cond_combined}: s += {weight}")
func_lines.append("  return s")

func_code = "\n".join(func_lines)

# Save for inspection
with open("/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/compiled_scorer.py", "w") as f:
    f.write(func_code)

print(f"Generated scoring function ({len(func_lines)} lines)")

# Compile and test
exec(compile(func_code, '<score>', 'exec'))
# 'score' is now defined

x_test = [65]*56
s = score(x_test)  # type: ignore
print(f"All A's: {s} (expected 331)")

# Now run fast SA
print("\nRunning optimized SA...")
best_ever = None
best_ever_score = 0
start = time.time()

for restart in range(1000):
    if time.time() - start > 180:
        break
    
    x = [random.randint(32, 126) for _ in range(56)]
    s = score(x)  # type: ignore
    best = x[:]
    best_s = s
    
    T = 30.0
    for step in range(500000):
        if time.time() - start > 180:
            break
        
        pos = random.randint(0, 55)
        old = x[pos]
        x[pos] = random.randint(32, 126)
        ns = score(x)  # type: ignore
        
        if ns >= s or (T > 0.01 and random.random() < 2.718281828 ** ((ns - s) / T)):
            s = ns
            if s > best_s:
                best_s = s
                best = x[:]
        else:
            x[pos] = old
        
        T *= 0.999995
    
    if best_s > best_ever_score:
        best_ever_score = best_s
        best_ever = best[:]
        print(f"[{time.time()-start:.1f}s] R{restart}: score={best_ever_score} - {''.join(chr(b) for b in best_ever)}")

print(f"\n=== FINAL ===")
print(f"Score: {best_ever_score} / 2563")
print(f"Input: {''.join(chr(b) for b in best_ever)}")
