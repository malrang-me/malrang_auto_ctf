#!/usr/bin/env python3
"""
Z3 solver for superONNX challenge.
Extracts all constraints from ONNX graph and solves them symbolically.
"""
import onnx
from onnx import numpy_helper
from z3 import *
import numpy as np
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Build initializer lookup
init_values = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_values[init.name] = int(arr.item())

# Z3 variables: 56 input bytes (BitVec 32 for arithmetic)
inp = [BitVec(f'x{i}', 32) for i in range(56)]

# Constraint: all inputs are printable ASCII (or at least 0-255)
solver = Solver()
for i in range(56):
    solver.add(inp[i] >= 32, inp[i] <= 126)

def resolve_value(name, local_consts, depth_prefix=""):
    """Resolve a value: either from input, initializer, or local constant."""
    if name in local_consts:
        return local_consts[name]
    if name in init_values:
        return BitVecVal(init_values[name], 32)
    if name == 'input_i32':
        return None  # special - used with Gather
    return None

def eval_node(node, local_consts, get_val):
    """Evaluate a node and return its output value."""
    op = node.op_type
    inputs = list(node.input)
    outputs = list(node.output)

    if op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = int(numpy_helper.to_array(attr.t).item())
                local_consts[outputs[0]] = BitVecVal(val, 32)
        return

    if op == 'Gather':
        # Gather(input_i32, index) -> inp[index]
        idx_val = get_val(inputs[1])
        if is_bv_value(idx_val):
            idx = idx_val.as_long()
            local_consts[outputs[0]] = inp[idx]
        return

    a = get_val(inputs[0]) if len(inputs) > 0 else None
    b = get_val(inputs[1]) if len(inputs) > 1 else None

    if op == 'Add':
        local_consts[outputs[0]] = a + b
    elif op == 'Sub':
        local_consts[outputs[0]] = a - b
    elif op == 'Mul':
        local_consts[outputs[0]] = a * b
    elif op == 'BitwiseAnd':
        local_consts[outputs[0]] = a & b
    elif op == 'BitwiseOr':
        local_consts[outputs[0]] = a | b
    elif op == 'BitwiseXor':
        local_consts[outputs[0]] = a ^ b
    elif op == 'Less':
        # Returns Bool in Z3
        local_consts[outputs[0]] = a < b  # signed comparison
    elif op == 'Greater':
        local_consts[outputs[0]] = a > b
    elif op == 'Not':
        local_consts[outputs[0]] = Not(a)
    elif op == 'Equal':
        local_consts[outputs[0]] = a == b

def extract_constraints_from_subgraph(sg, parent_consts):
    """Extract Z3 constraints from a subgraph (then-branch of an If)."""
    local = dict(parent_consts)  # inherit parent scope
    conditions = []

    def get_val(name):
        if name in local:
            return local[name]
        if name in init_values:
            return BitVecVal(init_values[name], 32)
        return None

    for node in sg.node:
        if node.op_type == 'If':
            # Get the condition
            cond = get_val(node.input[0])
            conditions.append(cond)

            # Recurse into then-branch
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    sub_conds = extract_constraints_from_subgraph(attr.g, local)
                    conditions.extend(sub_conds)
        else:
            eval_node(node, local, get_val)

    return conditions

# Parse main graph: collect pre-If nodes and If nodes
print("Extracting constraints from ONNX graph...")
start_time = time.time()

# Process nodes sequentially, building up the global scope
global_consts = {}

def global_get_val(name):
    if name in global_consts:
        return global_consts[name]
    if name in init_values:
        return BitVecVal(init_values[name], 32)
    return None

all_constraints = []
block_idx = 0

for node in graph.node:
    if node.op_type == 'If':
        # Get the outer condition
        cond = global_get_val(node.input[0])

        # Get then-branch constraints
        block_conds = [cond]
        for attr in node.attribute:
            if attr.name == 'then_branch':
                sub_conds = extract_constraints_from_subgraph(attr.g, global_consts)
                block_conds.extend(sub_conds)

        all_constraints.append(block_conds)
        block_idx += 1
    elif node.op_type in ('Reshape', 'Concat', 'ReduceSum'):
        pass  # skip aggregation nodes
    elif node.op_type == 'Cast':
        # Cast input to int32 - just mark it
        global_consts['input_i32'] = 'INPUT'
    else:
        eval_node(node, global_consts, global_get_val)

print(f"Extracted {len(all_constraints)} constraint blocks in {time.time()-start_time:.1f}s")
print(f"Constraints per block: {[len(c) for c in all_constraints[:10]]}")

# Add ALL constraints to solver (we want perfect score)
for block in all_constraints:
    for c in block:
        if c is not None:
            solver.add(c)

print(f"\nSolving with Z3...")
start_time = time.time()
result = solver.check()
print(f"Z3 result: {result} (took {time.time()-start_time:.1f}s)")

if result == sat:
    m = solver.model()
    flag_bytes = []
    for i in range(56):
        val = m.evaluate(inp[i])
        flag_bytes.append(val.as_long())

    flag = ''.join(chr(b) for b in flag_bytes)
    print(f"\n*** FLAG: {flag} ***")

    # Verify with ONNX runtime
    import onnxruntime as ort
    sess = ort.InferenceSession(MODEL_PATH)
    input_name = sess.get_inputs()[0].name
    output_name = sess.get_outputs()[0].name
    inp_arr = np.array(flag_bytes, dtype=np.uint8)
    score = int(sess.run([output_name], {input_name: inp_arr})[0])
    print(f"Verification score: {score}/2563")
else:
    print("UNSAT - constraints are contradictory")
    # Try with relaxed constraints (remove some)
    print("Trying with unsigned comparisons...")
