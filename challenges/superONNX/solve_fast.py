#!/usr/bin/env python3
"""Fast approach: compile ONNX constraints to Python, then optimize with SA."""

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

# Compile each block to a Python function
# We need to trace the computation graph for each block

def get_const_val(node):
    for attr in node.attribute:
        if attr.name == 'value':
            return int(onnx.numpy_helper.to_array(attr.t))
    return None

def compile_block(nodes_before_if, if_node, env_template):
    """Compile a block into a fast Python evaluator.
    Returns a function: eval_block(x) -> score (int)
    """
    # Generate Python code for this block
    lines = []
    
    def compile_nodes(nodes, env, prefix="", graph_obj=None):
        """Compile nodes to Python lines, returns condition chain."""
        conditions = []
        for n in nodes:
            op = n.op_type
            out = prefix + n.output[0]
            
            if op == 'Constant':
                val = get_const_val(n)
                env[n.output[0]] = val
                continue
            
            if op == 'Gather':
                idx_name = n.input[1]
                idx = env.get(idx_name, init_vals.get(idx_name))
                idx = int(idx)
                env[n.output[0]] = f'x[{idx}]'
                continue
            
            if op == 'Not':
                a = env[n.input[0]]
                env[n.output[0]] = f'(not ({a}))'
                continue
            
            if op == 'If':
                cond = env[n.input[0]]
                conditions.append(cond)
                # Process then_branch
                for attr in n.attribute:
                    if attr.name == 'then_branch':
                        then_env = dict(env)
                        inner_conds = compile_nodes(attr.g.node, then_env, prefix + "t_", attr.g)
                        conditions.extend(inner_conds)
                return conditions
            
            a_name = n.input[0]
            b_name = n.input[1]
            a = env.get(a_name)
            if a is None:
                if a_name in init_vals:
                    a = str(init_vals[a_name])
                else:
                    a = a_name
            b = env.get(b_name)
            if b is None:
                if b_name in init_vals:
                    b = str(init_vals[b_name])
                else:
                    b = b_name
            
            if isinstance(a, int): a = str(a)
            if isinstance(b, int): b = str(b)
            
            op_map = {
                'Add': f'(({a}) + ({b}))',
                'Sub': f'(({a}) - ({b}))',
                'Mul': f'(({a}) * ({b}))',
                'BitwiseAnd': f'(({a}) & ({b}))',
                'BitwiseOr': f'(({a}) | ({b}))',
                'BitwiseXor': f'(({a}) ^ ({b}))',
                'Less': f'(to_i32({a}) < to_i32({b}))',
                'Greater': f'(to_i32({a}) > to_i32({b}))',
            }
            
            if op in op_map:
                env[n.output[0]] = op_map[op]
            else:
                raise ValueError(f"Unknown op: {op}")
        
        return conditions
    
    return None  # placeholder

# Actually, let me just compile the whole thing into one big evaluator function
# by building an expression string for each block

def to_i32(val):
    """Convert to signed int32."""
    val = val & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val

def compile_if_chain(if_node, env):
    """Return (conditions_list, weight) where each condition is a lambda."""
    conditions = []
    
    # Get the condition expression
    cond_name = if_node.input[0]
    cond_expr = env[cond_name]
    conditions.append(cond_expr)
    
    # Get weight and inner conditions from then_branch
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            then_env = dict(env)
            weight = None
            for n in attr.g.node:
                if n.op_type == 'Constant':
                    val = get_const_val(n)
                    then_env[n.output[0]] = val
                    # Check if this is the output (leaf)
                    out_names = [o.name for o in attr.g.output]
                    if n.output[0] in out_names:
                        weight = val
                elif n.op_type == 'Gather':
                    idx = then_env.get(n.input[1], init_vals.get(n.input[1]))
                    idx = int(idx)
                    then_env[n.output[0]] = ('INPUT', idx)
                elif n.op_type == 'If':
                    inner_conds, inner_weight = compile_if_chain(n, then_env)
                    conditions.extend(inner_conds)
                    weight = inner_weight
                else:
                    # Binary/unary ops
                    a_name = n.input[0]
                    a = then_env.get(a_name, init_vals.get(a_name))
                    
                    if n.op_type == 'Not':
                        then_env[n.output[0]] = ('NOT', a)
                        continue
                    
                    b_name = n.input[1]
                    b = then_env.get(b_name, init_vals.get(b_name))
                    
                    op_tag = n.op_type.upper()
                    then_env[n.output[0]] = (op_tag, a, b)
            
            return conditions, weight
    
    return conditions, 0

# This is getting complex. Let me take a completely different approach:
# Just compile the entire graph to a numpy-friendly evaluator.

# Actually, the simplest fast approach: evaluate with numpy/python directly.

def eval_expr(expr, x):
    """Evaluate an expression tree with input x."""
    if isinstance(expr, int):
        return expr
    if isinstance(expr, tuple):
        if expr[0] == 'INPUT':
            return int(x[expr[1]])
        if expr[0] == 'NOT':
            return not eval_expr(expr[1], x)
        if expr[0] == 'ADD':
            return eval_expr(expr[1], x) + eval_expr(expr[2], x)
        if expr[0] == 'SUB':
            return eval_expr(expr[1], x) - eval_expr(expr[2], x)
        if expr[0] == 'MUL':
            return eval_expr(expr[1], x) * eval_expr(expr[2], x)
        if expr[0] == 'BITWISEAND':
            return eval_expr(expr[1], x) & eval_expr(expr[2], x)
        if expr[0] == 'BITWISEOR':
            return eval_expr(expr[1], x) | eval_expr(expr[2], x)
        if expr[0] == 'BITWISEXOR':
            return eval_expr(expr[1], x) ^ eval_expr(expr[2], x)
        if expr[0] == 'LESS':
            return to_i32(eval_expr(expr[1], x)) < to_i32(eval_expr(expr[2], x))
        if expr[0] == 'GREATER':
            return to_i32(eval_expr(expr[1], x)) > to_i32(eval_expr(expr[2], x))
    raise ValueError(f"Cannot eval: {expr}")

# Build expression trees for the main graph
env = {}
blocks = []  # list of (condition_trees, weight)

for node in graph.node:
    op = node.op_type
    
    if op == 'Cast':
        continue  # input_i32 = input
    
    if op == 'Gather':
        idx = init_vals.get(node.input[1])
        if idx is None:
            idx = env.get(node.input[1])
        idx = int(idx)
        env[node.output[0]] = ('INPUT', idx)
        continue
    
    if op == 'Not':
        a = env.get(node.input[0])
        env[node.output[0]] = ('NOT', a)
        continue
    
    if op in ('Reshape', 'Concat', 'ReduceSum'):
        continue
    
    if op == 'If':
        cond_expr = env[node.input[0]]
        conditions, weight = compile_if_chain(node, env)
        conditions[0] = cond_expr  # replace with actual expr tree
        blocks.append((conditions, weight))
        continue
    
    if len(node.input) < 2:
        continue
    
    a = env.get(node.input[0], init_vals.get(node.input[0]))
    b = env.get(node.input[1], init_vals.get(node.input[1]))
    
    if isinstance(a, (int, np.integer)): a = int(a)
    if isinstance(b, (int, np.integer)): b = int(b)
    
    env[node.output[0]] = (op.upper(), a, b)

print(f"Compiled {len(blocks)} blocks")

# Quick verify
def eval_score(x):
    score = 0
    for conditions, weight in blocks:
        all_true = True
        for cond in conditions:
            if not eval_expr(cond, x):
                all_true = False
                break
        if all_true:
            score += weight
    return score

x_test = [65] * 56
score = eval_score(x_test)
print(f"All A's score: {score} (expected 331)")

# Simulated annealing
print("\nRunning simulated annealing...")
best = list(range(32, 88))  # some initial guess
best_score = eval_score(best)
current = best[:]
current_score = best_score

T = 100.0
cooling = 0.9999
min_T = 0.01
iterations = 0
start_time = time.time()

while T > min_T and time.time() - start_time < 120:
    # Random mutation
    pos = random.randint(0, 55)
    old_val = current[pos]
    new_val = random.randint(32, 126)
    current[pos] = new_val
    new_score = eval_score(current)
    
    delta = new_score - current_score
    if delta > 0 or random.random() < np.exp(delta / T):
        current_score = new_score
        if new_score > best_score:
            best_score = new_score
            best = current[:]
            elapsed = time.time() - start_time
            print(f"  [{elapsed:.1f}s] New best: {best_score} - {''.join(chr(b) for b in best)}")
    else:
        current[pos] = old_val
    
    T *= cooling
    iterations += 1

print(f"\nDone. {iterations} iterations in {time.time()-start_time:.1f}s")
print(f"Best score: {best_score}")
print(f"Best input: {''.join(chr(b) for b in best)}")
