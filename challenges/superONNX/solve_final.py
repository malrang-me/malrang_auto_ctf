#!/usr/bin/env python3
"""Final solver: simplified scorer + iterative coordinate descent + GA."""

import onnx
import numpy as np
import random
import time
import copy

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

# For printable ASCII range, to_i32 is identity.
# But some intermediate expressions can go outside 0-255.
# After & 255 they're back in 0-255.
# For expressions without & 255, they can be negative (sub) or large (mul).
# We need to handle signed 32-bit comparison properly.

# Simplified: since inputs are 32-126, expressions like x[i]+x[j] are 64-252 (fits in int32 fine)
# x[i]*x[j] can be up to 126*126=15876 (fits fine)
# After & 255 max is 255
# So to_i32 is only needed when comparing raw expressions that could overflow 32 bits

def si(v):
    """Signed int32."""
    v = v & 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v

# Build compiled scorer as a simple Python function with minimal overhead
env = {}
code_lines = ["def score(x):", "  s=0"]

def expr_to_code(nodes, cur_env, indent="  "):
    """Convert nodes to Python code lines, return (lines, condition_codes, weight)."""
    lines = []
    conds = []
    weight = 0
    
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
                    inner_env = dict(cur_env)
                    _, inner_conds, inner_weight = expr_to_code(
                        list(attr.g.node), inner_env, indent)
                    conds.extend(inner_conds)
                    weight = inner_weight
                    # Check if leaf
                    for n2 in attr.g.node:
                        if n2.op_type == 'Constant':
                            val = get_const_val(n2)
                            if n2.output[0] in [o.name for o in attr.g.output]:
                                weight = val
            return lines, conds, weight
        
        if len(n.input) < 2:
            continue
        a = cur_env.get(n.input[0])
        if a is None: a = str(int(init_vals.get(n.input[0], 0)))
        b = cur_env.get(n.input[1])
        if b is None: b = str(int(init_vals.get(n.input[1], 0)))
        
        ops = {
            'Add': f'({a}+{b})', 'Sub': f'({a}-{b})', 'Mul': f'({a}*{b})',
            'BitwiseAnd': f'({a}&{b})', 'BitwiseOr': f'({a}|{b})', 'BitwiseXor': f'({a}^{b})',
            'Less': f'(si({a})<si({b}))', 'Greater': f'(si({a})>si({b}))',
        }
        if op in ops:
            cur_env[n.output[0]] = ops[op]
    
    return lines, conds, weight

# Process all blocks
for node in graph.node:
    op = node.op_type
    if op == 'Cast': continue
    if op in ('Reshape', 'Concat', 'ReduceSum'): continue
    if op == 'If':
        cond_expr = env[node.input[0]]
        # Get all conditions and weight
        then_env = dict(env)
        conds = [cond_expr]
        weight = 0
        for attr in node.attribute:
            if attr.name == 'then_branch':
                _, inner_conds, inner_weight = expr_to_code(
                    list(attr.g.node), then_env, "  ")
                conds.extend(inner_conds)
                weight = inner_weight
                # Check direct leaf
                for n2 in attr.g.node:
                    if n2.op_type == 'Constant':
                        val = get_const_val(n2)
                        if n2.output[0] in [o.name for o in attr.g.output]:
                            if inner_weight == 0:
                                weight = val
        
        if weight > 0:
            cond_str = " and ".join(conds)
            code_lines.append(f"  if {cond_str}: s+={weight}")
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
        env[node.output[0]] = f'(not ({env[node.input[0]]}))'
        continue
    if len(node.input) < 2: continue
    a = env.get(node.input[0])
    if a is None: a = str(int(init_vals.get(node.input[0], 0)))
    b = env.get(node.input[1])
    if b is None: b = str(int(init_vals.get(node.input[1], 0)))
    ops = {
        'Add': f'({a}+{b})', 'Sub': f'({a}-{b})', 'Mul': f'({a}*{b})',
        'BitwiseAnd': f'({a}&{b})', 'BitwiseOr': f'({a}|{b})', 'BitwiseXor': f'({a}^{b})',
        'Less': f'(si({a})<si({b}))', 'Greater': f'(si({a})>si({b}))',
    }
    if op in ops:
        env[node.output[0]] = ops[op]

code_lines.append("  return s")
code = "\n".join(code_lines)

# Compile
_ns = {'si': si}
exec(compile(code, '<score>', 'exec'), _ns)
score = _ns['score']

x_test = [65]*56
print(f"All A's: {score(x_test)}")

# Approach: Genetic Algorithm with large population
POP_SIZE = 200
GENERATIONS = 5000
ELITE = 20
MUTATION_RATE = 0.15

def random_individual():
    return [random.randint(32, 126) for _ in range(56)]

def mutate(ind, rate=MUTATION_RATE):
    child = ind[:]
    for i in range(56):
        if random.random() < rate:
            child[i] = random.randint(32, 126)
    return child

def crossover(a, b):
    pt = random.randint(1, 55)
    return a[:pt] + b[pt:]

# Initialize population
population = [random_individual() for _ in range(POP_SIZE)]
best_ever = None
best_ever_score = 0
start = time.time()

for gen in range(GENERATIONS):
    if time.time() - start > 300:  # 5 min
        break
    
    # Evaluate
    scores_pop = [(score(ind), ind) for ind in population]
    scores_pop.sort(key=lambda x: -x[0])
    
    if scores_pop[0][0] > best_ever_score:
        best_ever_score = scores_pop[0][0]
        best_ever = scores_pop[0][1][:]
        print(f"[{time.time()-start:.1f}s] Gen {gen}: best={best_ever_score} - {''.join(chr(b) for b in best_ever)}")
    
    # Selection: keep elite
    new_pop = [ind[:] for _, ind in scores_pop[:ELITE]]
    
    # Fill rest with crossover + mutation
    while len(new_pop) < POP_SIZE:
        # Tournament selection
        t1 = random.sample(scores_pop[:POP_SIZE//2], 2)
        p1 = max(t1, key=lambda x: x[0])[1]
        t2 = random.sample(scores_pop[:POP_SIZE//2], 2)
        p2 = max(t2, key=lambda x: x[0])[1]
        
        child = crossover(p1, p2)
        child = mutate(child)
        new_pop.append(child)
    
    population = new_pop
    
    # Periodically do per-byte optimization on best
    if gen % 50 == 49:
        x = best_ever[:]
        improved = True
        while improved:
            improved = False
            for pos in range(56):
                bv = x[pos]
                bs = score(x)
                for v in range(32, 127):
                    x[pos] = v
                    s = score(x)
                    if s > bs:
                        bs = s
                        bv = v
                        improved = True
                x[pos] = bv
        if bs > best_ever_score:
            best_ever_score = bs
            best_ever = x[:]
            print(f"[{time.time()-start:.1f}s] Refined: best={best_ever_score} - {''.join(chr(b) for b in best_ever)}")
        # Inject back
        population[0] = best_ever[:]

print(f"\n=== FINAL ===")
print(f"Score: {best_ever_score} / 2563")
print(f"FLAG: {''.join(chr(b) for b in best_ever)}")
