#!/usr/bin/env python3
"""
Z3 solver - fixed: use np.int32 overflow semantics properly.
The key issue: np.int32 overflow wraps around, but Z3 BitVec(32) does too.
The real issue might be with how Python handles & on numpy int32 vs Z3 BitVec.

Actually, the issue is likely that some operations produce values that need
int32 truncation. In numpy, int32 * int32 can overflow. In Z3 BitVec(32),
multiplication also wraps mod 2^32. So they should match.

Let me try a different approach: trace each block's constraints manually
and build Z3 constraints that are verified correct.
"""
import onnx
from onnx import numpy_helper
from z3 import *
import numpy as np
import onnxruntime as ort
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_map[init.name] = int(arr.item())

x = [BitVec(f'x{i}', 32) for i in range(56)]

def get_val(name, env):
    if name in env: return env[name]
    if name in init_map: return BitVecVal(init_map[name], 32)
    return None

def process_node_sym(node, env):
    """Process node symbolically, return True if successful."""
    op = node.op_type
    ins = list(node.input)
    outs = list(node.output)

    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                env[outs[0]] = BitVecVal(int(numpy_helper.to_array(attr.t).item()), 32)
        return True

    if op == 'Gather':
        idx = get_val(ins[1], env)
        if idx is not None and is_bv_value(idx):
            env[outs[0]] = x[idx.as_long()]
            return True
        return False

    a = get_val(ins[0], env) if len(ins) > 0 else None
    b = get_val(ins[1], env) if len(ins) > 1 else None

    if a is None:
        return False

    if op == 'Add' and b is not None: env[outs[0]] = a + b
    elif op == 'Sub' and b is not None: env[outs[0]] = a - b
    elif op == 'Mul' and b is not None: env[outs[0]] = a * b
    elif op == 'BitwiseAnd' and b is not None: env[outs[0]] = a & b
    elif op == 'BitwiseOr' and b is not None: env[outs[0]] = a | b
    elif op == 'BitwiseXor' and b is not None: env[outs[0]] = a ^ b
    elif op == 'Less' and b is not None: env[outs[0]] = a < b  # signed
    elif op == 'Greater' and b is not None: env[outs[0]] = a > b  # signed
    elif op == 'Not': env[outs[0]] = Not(a)
    elif op == 'Equal' and b is not None: env[outs[0]] = a == b
    else:
        return False
    return True

def extract_block_constraint(pre_nodes, if_node, main_env):
    """Extract the full constraint for one block (all nested Ifs must be True).
    Returns a single Z3 formula: And(outer_cond, level1_cond, level2_cond, ...)
    """
    env = dict(main_env)

    # Process pre-If nodes
    for node in pre_nodes:
        process_node_sym(node, env)

    # Get outer condition
    outer_cond = get_val(if_node.input[0], env)
    if outer_cond is None:
        return None

    conditions = [outer_cond]

    # Recursively extract nested If conditions from then-branches
    def extract_nested(sg, parent_env):
        env = dict(parent_env)
        nested_conds = []
        for node in sg.node:
            if node.op_type == 'If':
                cond = get_val(node.input[0], env)
                if cond is not None:
                    nested_conds.append(cond)
                for attr in node.attribute:
                    if attr.name == 'then_branch':
                        nested_conds.extend(extract_nested(attr.g, env))
            else:
                process_node_sym(node, env)
        return nested_conds

    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            conditions.extend(extract_nested(attr.g, env))

    return And(*conditions) if conditions else None

# Parse main graph into blocks
print("Parsing graph into blocks...")
blocks = []  # list of (pre_nodes, if_node)
current_pre = []
main_env = {}  # shared env across blocks (for variables computed between blocks)

for node in graph.node:
    if node.op_type == 'Cast':
        continue
    if node.op_type in ('Reshape', 'Concat', 'ReduceSum'):
        continue
    if node.op_type == 'If':
        blocks.append((list(current_pre), node))
        current_pre = []
    else:
        current_pre.append(node)
        # Also process into main_env so later blocks can reference earlier values
        process_node_sym(node, main_env)

print(f"Total blocks: {len(blocks)}")

# Extract constraints for each block
all_constraints = []
for i, (pre, if_node) in enumerate(blocks):
    c = extract_block_constraint(pre, if_node, main_env)
    all_constraints.append(c)

valid = sum(1 for c in all_constraints if c is not None)
print(f"Valid constraints: {valid}/{len(all_constraints)}")

# Verify: check a specific input
print("\n=== Verification ===")
test_vals = [65]*56  # all 'A'

# Concrete evaluation
def eval_constraint_concrete(constraint, vals):
    """Evaluate a Z3 constraint with concrete values."""
    substitutions = [(x[i], BitVecVal(vals[i], 32)) for i in range(56)]
    concrete = substitute(constraint, *substitutions)
    return is_true(simplify(concrete))

# Check first 5 blocks
sess = ort.InferenceSession(MODEL_PATH)
test_arr = np.array(test_vals, dtype=np.uint8)

# Get per-block results from ONNX (need intermediate outputs)
# Instead, use our verified manual evaluator
from verify_constraints import eval_main_graph
block_results, _ = eval_main_graph(test_arr)

mismatches = 0
for i in range(len(all_constraints)):
    c = all_constraints[i]
    if c is None:
        continue
    z3_result = eval_constraint_concrete(c, test_vals)
    onnx_block_pass = block_results[i] > 0

    if z3_result != onnx_block_pass:
        mismatches += 1
        if mismatches <= 5:
            print(f"  MISMATCH block {i}: Z3={z3_result}, ONNX={'pass' if onnx_block_pass else 'fail'}")
            print(f"    Constraint: {c}")

print(f"Mismatches: {mismatches}/{len(all_constraints)}")

if mismatches == 0:
    print("All constraints match! Solving...")
    solver = Solver()
    for i in range(56):
        solver.add(x[i] >= 0, x[i] <= 255)
    for c in all_constraints:
        if c is not None:
            solver.add(c)
    solver.set('timeout', 120000)
    start = time.time()
    result = solver.check()
    print(f"Result: {result} ({time.time()-start:.1f}s)")
    if result == sat:
        m = solver.model()
        flag_bytes = [m.evaluate(x[i]).as_long() for i in range(56)]
        flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in flag_bytes)
        print(f"FLAG: {flag}")
else:
    print(f"\n{mismatches} mismatches found - constraint encoding is wrong!")
    print("Need to fix encoding before solving.")
