#!/usr/bin/env python3
"""Stage 2: Extract all constraints from ONNX model and solve with Z3."""

import onnx
import numpy as np
from collections import defaultdict

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Build lookup for initializer values
init_vals = {}
for init in graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    init_vals[init.name] = arr

# Build node output map
node_by_output = {}
for node in graph.node:
    for out in node.output:
        node_by_output[out] = node

# Print the last few nodes to understand the structure
print("=== LAST 20 NODES ===")
for i, node in enumerate(graph.node[-20:]):
    print(f"  [{len(graph.node)-20+i}] {node.op_type}: inputs={list(node.input)}, outputs={list(node.output)}")
    if node.op_type == 'If':
        # Check the then/else branches
        for attr in node.attribute:
            print(f"    attr {attr.name}: graph with {len(attr.g.node)} nodes")
            if len(attr.g.node) <= 3:
                for n in attr.g.node:
                    print(f"      {n.op_type}: inputs={list(n.input)}, outputs={list(n.output)}")
                for init2 in attr.g.initializer:
                    arr2 = onnx.numpy_helper.to_array(init2)
                    print(f"      init: {init2.name} = {arr2}")
                for out2 in attr.g.output:
                    print(f"      output: {out2.name}")

# Analyze one If node in detail
print("\n=== FIRST IF NODE ANALYSIS ===")
for node in graph.node:
    if node.op_type == 'If':
        print(f"If: input={list(node.input)}, output={list(node.output)}")
        for attr in node.attribute:
            print(f"  Branch '{attr.name}':")
            print(f"    Nodes: {len(attr.g.node)}")
            for n in attr.g.node:
                print(f"      {n.op_type}: inputs={list(n.input)}, outputs={list(n.output)}")
            for init2 in attr.g.initializer:
                arr2 = onnx.numpy_helper.to_array(init2)
                print(f"      init: {init2.name} = {arr2}")
            for out2 in attr.g.output:
                print(f"      output: {out2.name}")
        break

# Also look at the Concat and ReduceSum at the end
print("\n=== CONCAT NODE ===")
for node in graph.node:
    if node.op_type == 'Concat':
        print(f"Concat: inputs={list(node.input)[:20]}... ({len(list(node.input))} total)")
        print(f"  outputs={list(node.output)}")
    if node.op_type == 'ReduceSum':
        print(f"ReduceSum: inputs={list(node.input)}, outputs={list(node.output)}")
