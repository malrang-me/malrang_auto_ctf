#!/usr/bin/env python3
"""Fast SA with compiled numpy evaluator + multi-restart."""

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

def to_i32(val):
    val = int(val) & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val

def get_const_val(node):
    for attr in node.attribute:
        if attr.name == 'value':
            return int(onnx.numpy_helper.to_array(attr.t))
    return None

# Compile blocks to tuples for fast evaluation
# Each constraint: (op, arg1, arg2) where args can be ('idx', i) or ('val', v) or ('expr', ...)
def compile_expr(node, env):
    """Return an expression tuple for fast evaluation."""
    op = node.op_type
    if op == 'Constant':
        val = get_const_val(node)
        env[node.output[0]] = ('val', val)
        return
    if op == 'Gather':
        idx = env.get(node.input[1])
        if idx is None:
            idx = init_vals.get(node.input[1])
        if isinstance(idx, tuple):
            idx = idx[1]  # ('val', v) -> v
        else:
            idx = int(idx)
        env[node.output[0]] = ('idx', idx)
        return
    if op == 'Not':
        a = env.get(node.input[0])
        env[node.output[0]] = ('not', a)
        return
    if len(node.input) < 2:
        return
    a = env.get(node.input[0])
    if a is None:
        v = init_vals.get(node.input[0])
        a = ('val', int(v)) if v is not None else None
    b = env.get(node.input[1])
    if b is None:
        v = init_vals.get(node.input[1])
        b = ('val', int(v)) if v is not None else None
    
    op_map = {'Add':'add','Sub':'sub','Mul':'mul','BitwiseAnd':'and','BitwiseOr':'or',
              'BitwiseXor':'xor','Less':'lt','Greater':'gt'}
    if op in op_map:
        env[node.output[0]] = (op_map[op], a, b)

def compile_if(if_node, env):
    """Return list of compiled condition expressions and weight."""
    conds = []
    cond = env[if_node.input[0]]
    conds.append(cond)
    
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            then_env = dict(env)
            weight = 0
            for n in attr.g.node:
                if n.op_type == 'If':
                    inner_conds, inner_weight = compile_if(n, then_env)
                    conds.extend(inner_conds)
                    weight = inner_weight
                elif n.op_type == 'Constant':
                    val = get_const_val(n)
                    then_env[n.output[0]] = ('val', val)
                    if n.output[0] in [o.name for o in attr.g.output]:
                        weight = val
                else:
                    compile_expr(n, then_env)
            return conds, weight
    return conds, 0

# Build compiled blocks
env = {}
blocks = []  # (cond_exprs, weight)

for node in graph.node:
    op = node.op_type
    if op == 'Cast':
        continue
    if op in ('Reshape', 'Concat', 'ReduceSum'):
        continue
    if op == 'If':
        cond_expr = env[node.input[0]]
        conds, weight = compile_if(node, env)
        conds[0] = cond_expr
        blocks.append((conds, weight))
        continue
    compile_expr(node, env)

print(f"Compiled {len(blocks)} blocks")

# Fast evaluator
def fast_eval(expr, x):
    tag = expr[0]
    if tag == 'idx': return x[expr[1]]
    if tag == 'val': return expr[1]
    if tag == 'not': return not fast_eval(expr[1], x)
    if tag == 'add': return fast_eval(expr[1], x) + fast_eval(expr[2], x)
    if tag == 'sub': return fast_eval(expr[1], x) - fast_eval(expr[2], x)
    if tag == 'mul': return fast_eval(expr[1], x) * fast_eval(expr[2], x)
    if tag == 'and': return fast_eval(expr[1], x) & fast_eval(expr[2], x)
    if tag == 'or': return fast_eval(expr[1], x) | fast_eval(expr[2], x)
    if tag == 'xor': return fast_eval(expr[1], x) ^ fast_eval(expr[2], x)
    if tag == 'lt': return to_i32(fast_eval(expr[1], x)) < to_i32(fast_eval(expr[2], x))
    if tag == 'gt': return to_i32(fast_eval(expr[1], x)) > to_i32(fast_eval(expr[2], x))
    raise ValueError(f"Unknown tag: {tag}")

def score(x):
    total = 0
    for conds, weight in blocks:
        ok = True
        for c in conds:
            if not fast_eval(c, x):
                ok = False
                break
        if ok:
            total += weight
    return total

# Verify
x_test = [65]*56
print(f"All A's: {score(x_test)} (expected 331)")

# Multi-restart SA with aggressive mutations
best_ever = None
best_ever_score = 0
start = time.time()

for restart in range(100):
    if time.time() - start > 240:
        break
    
    # Random start
    x = [random.randint(32, 126) for _ in range(56)]
    s = score(x)
    best = x[:]
    best_s = s
    
    T = 50.0
    for step in range(200000):
        if time.time() - start > 240:
            break
        
        # Mutate 1-3 positions
        n_mut = random.choice([1, 1, 1, 2, 3])
        old_vals = []
        positions = random.sample(range(56), n_mut)
        for pos in positions:
            old_vals.append((pos, x[pos]))
            x[pos] = random.randint(32, 126)
        
        new_s = score(x)
        delta = new_s - s
        
        if delta > 0 or (T > 0.01 and random.random() < np.exp(delta / T)):
            s = new_s
            if s > best_s:
                best_s = s
                best = x[:]
        else:
            for pos, val in old_vals:
                x[pos] = val
        
        T *= 0.99999
    
    if best_s > best_ever_score:
        best_ever_score = best_s
        best_ever = best[:]
        elapsed = time.time() - start
        print(f"[{elapsed:.1f}s] Restart {restart}: New best = {best_ever_score} - {''.join(chr(b) for b in best_ever)}")

print(f"\n=== FINAL RESULT ===")
print(f"Best score: {best_ever_score} / 2563")
print(f"Best input: {''.join(chr(b) for b in best_ever)}")
