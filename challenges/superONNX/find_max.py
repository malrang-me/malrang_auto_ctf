#!/usr/bin/env python3
"""Find the maximum possible score by examining all block return values."""
import onnx
from onnx import numpy_helper

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

def find_deepest_then_value(sg, depth=0):
    """Recursively find the value returned by the deepest then branch."""
    for node in sg.node:
        if node.op_type == 'If':
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    return find_deepest_then_value(attr.g, depth+1)
        elif node.op_type == 'Constant' and 'out' in node.output[0]:
            for a in node.attribute:
                if a.name == 'value':
                    return numpy_helper.to_array(a.t).item()
    # Check for Constant outputs
    for node in sg.node:
        if node.op_type == 'Constant':
            for a in node.attribute:
                if a.name == 'value':
                    val = numpy_helper.to_array(a.t).item()
                    if val != 0:  # Skip else-branch zeros
                        return val
    return None

total_max = 0
block_values = []
if_nodes = [n for n in graph.node if n.op_type == 'If']

# Only top-level If nodes (not nested ones - those are in subgraphs)
top_if_nodes = []
for node in graph.node:
    if node.op_type == 'If':
        top_if_nodes.append(node)

for i, if_node in enumerate(top_if_nodes):
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            val = find_deepest_then_value(attr.g)
            if val is not None:
                block_values.append(val)
                total_max += val
            else:
                block_values.append('?')

print(f"Total blocks: {len(top_if_nodes)}")
print(f"Block values (first 20): {block_values[:20]}")
print(f"Total max score: {total_max}")
print(f"Min value: {min(v for v in block_values if isinstance(v, (int, float)))}")
print(f"Max value: {max(v for v in block_values if isinstance(v, (int, float)))}")

from collections import Counter
val_counts = Counter(block_values)
print(f"Value distribution: {val_counts.most_common()}")
