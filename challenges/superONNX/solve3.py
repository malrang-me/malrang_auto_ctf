#!/usr/bin/env python3
"""Extract constraints from ONNX and solve with Z3.

Strategy: Instead of parsing the complex nested If graph structure,
use ONNX runtime to evaluate the model and use Z3 to find input that
maximizes the score. But since score depends on 440 independent boolean
checks, we can try to understand each check.

Actually, simpler approach: use onnxruntime to run the model as an oracle,
and brute-force byte by byte. But 56 bytes = too large.

Better: Parse the graph symbolically. Each "block" is a chain of conditions.
We need to trace each condition back to input bytes and constants.
"""

import onnx
import numpy as np

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Build initializer lookup
init_vals = {}
for init in graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    init_vals[init.name] = arr

# Let's look at the structure more carefully by examining several blocks
# Each block starts with some operations on input, then an If node
# The If's then_branch may have nested If nodes (deeper conditions)

# Let me trace a few blocks to understand the pattern

def get_const_val(node):
    """Get constant value from a Constant node."""
    for attr in node.attribute:
        if attr.name == 'value':
            return onnx.numpy_helper.to_array(attr.t)
    return None

def trace_if_branch(branch_graph, depth=0):
    """Trace an If branch to extract constraints."""
    prefix = "  " * depth
    nodes = list(branch_graph.node)
    inits = {}
    for init in branch_graph.initializer:
        inits[init.name] = onnx.numpy_helper.to_array(init)
    
    result = []
    for n in nodes:
        if n.op_type == 'Constant':
            val = get_const_val(n)
            inits[n.output[0]] = val
        result.append((n.op_type, list(n.input), list(n.output), inits.copy()))
    
    # Check for nested If
    for n in nodes:
        if n.op_type == 'If':
            for attr in n.attribute:
                if attr.name == 'then_branch':
                    inner = trace_if_branch(attr.g, depth+1)
                    result.append(('NESTED_THEN', inner, None, None))
                if attr.name == 'else_branch':
                    inner = trace_if_branch(attr.g, depth+1)
                    result.append(('NESTED_ELSE', inner, None, None))
    
    return result

# Let's just look at block 0 in detail
print("=== BLOCK 0 DETAILED TRACE ===")
# Nodes before first If: indices 1-12 are the operations, node 13 is If
for i, node in enumerate(graph.node[:14]):
    if node.op_type == 'Gather':
        idx_name = node.input[1]
        idx_val = int(init_vals[idx_name])
        print(f"  [{i}] {node.output[0]} = input[{idx_val}]")
    elif node.op_type == 'Add':
        print(f"  [{i}] {node.output[0]} = {node.input[0]} + {node.input[1]}")
    elif node.op_type == 'Sub':
        val_name = node.input[0]
        if val_name in init_vals:
            print(f"  [{i}] {node.output[0]} = {int(init_vals[val_name])} - {node.input[1]}")
        else:
            print(f"  [{i}] {node.output[0]} = {node.input[0]} - {node.input[1]}")
    elif node.op_type == 'BitwiseAnd':
        mask_name = node.input[1]
        if mask_name in init_vals:
            print(f"  [{i}] {node.output[0]} = {node.input[0]} & {int(init_vals[mask_name])}")
        else:
            print(f"  [{i}] {node.output[0]} = {node.input[0]} & {node.input[1]}")
    elif node.op_type == 'Mul':
        print(f"  [{i}] {node.output[0]} = {node.input[0]} * {node.input[1]}")
    elif node.op_type == 'Less':
        print(f"  [{i}] {node.output[0]} = {node.input[0]} < {node.input[1]}")
    elif node.op_type == 'Greater':
        imm_name = node.input[1]
        if imm_name in init_vals:
            print(f"  [{i}] {node.output[0]} = {node.input[0]} > {int(init_vals[imm_name])}")
        else:
            print(f"  [{i}] {node.output[0]} = {node.input[0]} > {node.input[1]}")
    elif node.op_type == 'Not':
        print(f"  [{i}] {node.output[0]} = NOT {node.input[0]}")
    elif node.op_type == 'Cast':
        print(f"  [{i}] {node.output[0]} = cast({node.input[0]})")
    elif node.op_type == 'If':
        print(f"  [{i}] IF {node.input[0]} -> {node.output[0]}")
        for attr in node.attribute:
            if attr.name == 'then_branch':
                print(f"    THEN branch ({len(attr.g.node)} nodes):")
                for n2 in attr.g.node:
                    if n2.op_type == 'Constant':
                        val = get_const_val(n2)
                        print(f"      {n2.output[0]} = const({val})")
                    elif n2.op_type == 'Gather':
                        # Find the index constant
                        idx_name = n2.input[1]
                        # Look in this subgraph's constants
                        for n3 in attr.g.node:
                            if n3.op_type == 'Constant' and n3.output[0] == idx_name:
                                val = get_const_val(n3)
                                print(f"      {n2.output[0]} = input[{int(val)}]")
                                break
                    else:
                        print(f"      {n2.op_type}: {list(n2.input)} -> {list(n2.output)}")
            if attr.name == 'else_branch':
                print(f"    ELSE branch ({len(attr.g.node)} nodes):")
                for n2 in attr.g.node:
                    if n2.op_type == 'Constant':
                        val = get_const_val(n2)
                        print(f"      {n2.output[0]} = const({val})")

# Count nesting depth of If nodes
print("\n=== IF NESTING ANALYSIS ===")
def count_if_depth(g, depth=0):
    max_d = depth
    for n in g.node:
        if n.op_type == 'If':
            for attr in n.attribute:
                if attr.name == 'then_branch':
                    d = count_if_depth(attr.g, depth+1)
                    max_d = max(max_d, d)
    return max_d

# Check overall graph
overall_depth = count_if_depth(graph)
print(f"Overall max If nesting depth: {overall_depth}")

# Check a few If nodes
for node in graph.node:
    if node.op_type == 'If':
        for attr in node.attribute:
            if attr.name == 'then_branch':
                d = count_if_depth(attr.g, 1)
                print(f"  {node.output[0]}: then branch depth = {d}")
                break
        break
