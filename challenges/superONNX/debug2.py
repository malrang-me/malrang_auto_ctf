#!/usr/bin/env python3
"""Debug: Check what leaf branches return."""

import onnx
import numpy as np

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

def get_const_val(node):
    for attr in node.attribute:
        if attr.name == 'value':
            return onnx.numpy_helper.to_array(attr.t)
    return None

def analyze_if(if_node, depth=0):
    """Recursively analyze If node, showing then/else values."""
    prefix = "  " * depth
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            g = attr.g
            has_inner_if = False
            for n in g.node:
                if n.op_type == 'If':
                    has_inner_if = True
                    print(f"{prefix}THEN -> nested If:")
                    analyze_if(n, depth+1)
            if not has_inner_if:
                # Leaf: find what it returns
                for n in g.node:
                    if n.op_type == 'Constant':
                        val = get_const_val(n)
                        # Check if this is the output
                        if n.output[0] in [o.name for o in g.output]:
                            print(f"{prefix}THEN -> returns {val}")
                # Also check if output comes from a non-constant
                out_names = [o.name for o in g.output]
                for n in g.node:
                    if any(o in out_names for o in n.output) and n.op_type == 'Constant':
                        val = get_const_val(n)
                        print(f"{prefix}THEN leaf = {val}")
                        
        if attr.name == 'else_branch':
            g = attr.g
            has_inner_if = False
            for n in g.node:
                if n.op_type == 'If':
                    has_inner_if = True
                    print(f"{prefix}ELSE -> nested If:")
                    analyze_if(n, depth+1)
            if not has_inner_if:
                for n in g.node:
                    if n.op_type == 'Constant':
                        val = get_const_val(n)
                        print(f"{prefix}ELSE leaf = {val}")

# Analyze first 3 blocks
block_id = 0
for node in graph.node:
    if node.op_type == 'If' and block_id < 3:
        print(f"\n=== Block {block_id}: {node.output[0]} ===")
        analyze_if(node)
        block_id += 1
    if block_id >= 3:
        break
