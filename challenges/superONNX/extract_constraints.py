#!/usr/bin/env python3
"""
Extract constraint structure from ONNX model for Z3 solving.
Each of the 440 If-chains encodes a constraint on the input bytes.
We need to trace each chain to extract the conditions.
"""
import onnx
from onnx import numpy_helper
import json

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Build lookup tables
init_values = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_values[init.name] = arr

# Map output_name -> node
output_to_node = {}
for node in graph.node:
    for out in node.output:
        output_to_node[out] = node

# Now trace the structure. Each top-level block (b0, b1, ..., b439) has:
# - Some arithmetic on input bytes
# - A comparison (Less, Greater, etc.)
# - An If node that may contain nested computations and more If nodes
# - The deepest If's then-branch returns 1 (constraint satisfied), else returns 0

def extract_constant_from_subgraph(sg, name):
    """Find value of a Constant node in subgraph."""
    for node in sg.node:
        if node.op_type == 'Constant' and node.output[0] == name:
            for attr in node.attribute:
                if attr.name == 'value':
                    return numpy_helper.to_array(attr.t).item()
    for init in sg.initializer:
        if init.name == name:
            return numpy_helper.to_array(init).item()
    return None

def trace_if_chain(if_node, depth=0):
    """Recursively trace an If node to extract constraints."""
    constraints = []

    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            sg = attr.g
            # Extract operations in then branch
            ops = []
            for node in sg.node:
                if node.op_type == 'If':
                    # Recursive - get its input condition
                    sub_constraints = trace_if_chain(node, depth+1)
                    constraints.extend(sub_constraints)
                elif node.op_type in ('Constant',):
                    pass
                else:
                    op_info = {
                        'op': node.op_type,
                        'inputs': list(node.input),
                        'outputs': list(node.output),
                    }
                    ops.append(op_info)
            constraints.append({'depth': depth, 'then_ops': ops})

        elif attr.name == 'else_branch':
            sg = attr.g
            # Check what else returns
            for node in sg.node:
                if node.op_type == 'Constant':
                    for a in node.attribute:
                        if a.name == 'value':
                            val = numpy_helper.to_array(a.t).item()
                            constraints.append({'depth': depth, 'else_value': val})

    return constraints

# Let's just look at the main graph structure more carefully
# Focus on the first few constraint blocks

print("=== TRACING CONSTRAINT BLOCKS ===")

# The main graph nodes before the first If tell us the pattern
# Nodes: Cast, then repeating patterns of Gather/Add/Sub/Mul/BitwiseAnd/BitwiseOr/BitwiseXor/Less/Greater/Not -> If

# Let's collect all top-level (non-If) nodes between If nodes to see the pattern
blocks = []
current_block = []
for node in graph.node:
    if node.op_type == 'If':
        blocks.append((current_block, node))
        current_block = []
    elif node.op_type in ('Reshape', 'Concat', 'ReduceSum'):
        pass  # skip final aggregation
    else:
        current_block.append(node)

print(f"Total constraint blocks: {len(blocks)}")

# Analyze first 5 blocks in detail
for bi, (pre_nodes, if_node) in enumerate(blocks[:5]):
    print(f"\n--- Block {bi} ---")
    print(f"  Pre-If nodes: {len(pre_nodes)}")
    for n in pre_nodes:
        inputs_resolved = []
        for inp in n.input:
            if inp in init_values:
                inputs_resolved.append(f"{inp}={init_values[inp].item()}")
            else:
                inputs_resolved.append(inp)
        print(f"    {n.op_type}({', '.join(inputs_resolved)}) -> {list(n.output)}")

    print(f"  If input: {list(if_node.input)}")

    # Trace the If
    for attr in if_node.attribute:
        sg = attr.g
        print(f"  {attr.name}:")
        for sn in sg.node:
            if sn.op_type == 'Constant':
                for a in sn.attribute:
                    if a.name == 'value':
                        val = numpy_helper.to_array(a.t)
                        print(f"      Constant {sn.output[0]} = {val.item()}")
            elif sn.op_type == 'If':
                print(f"      NESTED If input={list(sn.input)}")
                # Trace one more level
                for sa in sn.attribute:
                    ssg = sa.g
                    print(f"        {sa.name}:")
                    for ssn in ssg.node:
                        if ssn.op_type == 'Constant':
                            for a2 in ssn.attribute:
                                if a2.name == 'value':
                                    val = numpy_helper.to_array(a2.t)
                                    print(f"            Constant {ssn.output[0]} = {val.item()}")
                        elif ssn.op_type == 'If':
                            print(f"            NESTED If (depth 2) input={list(ssn.input)}")
                        else:
                            print(f"            {ssn.op_type}({list(ssn.input)}) -> {list(ssn.output)}")
            else:
                print(f"      {sn.op_type}({list(sn.input)}) -> {list(sn.output)}")
