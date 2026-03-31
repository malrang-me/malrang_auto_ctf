#!/usr/bin/env python3
"""Stage 2: Deep analysis of ONNX graph to understand constraint structure."""
import onnx
from onnx import numpy_helper

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# Understand the If nodes - they likely encode constraint checks
# Each If node has then/else subgraphs

print("=== ANALYZING If NODES ===")
if_nodes = [n for n in graph.node if n.op_type == 'If']
print(f"Total If nodes: {len(if_nodes)}")

# Look at first few If nodes
for i, node in enumerate(if_nodes[:3]):
    print(f"\n--- If node {i} ---")
    print(f"  Input: {list(node.input)}")
    print(f"  Output: {list(node.output)}")
    for attr in node.attribute:
        print(f"  Attribute: {attr.name}")
        if attr.g:  # subgraph
            sg = attr.g
            print(f"    Subgraph nodes: {len(sg.node)}")
            print(f"    Subgraph outputs: {[o.name for o in sg.output]}")
            for sn in sg.node:
                print(f"      {sn.op_type} inputs={list(sn.input)} outputs={list(sn.output)}")
            for si in sg.initializer:
                arr = numpy_helper.to_array(si)
                print(f"      Init: {si.name} = {arr}")

# Check last nodes - how is total_score computed?
print("\n=== LAST 30 NODES ===")
for i, node in enumerate(graph.node[-30:]):
    print(f"  [{len(graph.node)-30+i}] {node.op_type} name={node.name} inputs={list(node.input)} outputs={list(node.output)}")

# Check the Concat and ReduceSum
print("\n=== CONCAT/REDUCESUM NODES ===")
for node in graph.node:
    if node.op_type in ('Concat', 'ReduceSum'):
        print(f"  {node.op_type} inputs={list(node.input)[:10]}... ({len(node.input)} total) outputs={list(node.output)}")
        if node.op_type == 'Concat':
            print(f"    Full inputs: {list(node.input)}")
