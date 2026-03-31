#!/usr/bin/env python3
"""Verify with ONNX Runtime: try some inputs and see scores."""
import onnxruntime as ort
import numpy as np

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
sess = ort.InferenceSession(MODEL_PATH)

# Input spec: shape (56,), elem_type 2 = UINT8
inp_meta = sess.get_inputs()[0]
out_meta = sess.get_outputs()[0]
print(f"Input: {inp_meta.name}, shape={inp_meta.shape}, type={inp_meta.type}")
print(f"Output: {out_meta.name}, shape={out_meta.shape}, type={out_meta.type}")

# Try all A's
test1 = np.array([ord('A')] * 56, dtype=np.uint8)
result1 = sess.run(None, {'input': test1})
print(f"All A's: score = {result1[0]}")

# Try HSPACE{...}
test2 = np.array([ord(c) for c in "HSPACE{" + "A" * 48 + "}"], dtype=np.uint8)
result2 = sess.run(None, {'input': test2})
print(f"HSPACE{{A*48}}: score = {result2[0]}")

# Try random inputs
import random
best_score = 0
best_inp = None
for _ in range(10000):
    test = np.array([random.randint(32, 126) for _ in range(56)], dtype=np.uint8)
    result = sess.run(None, {'input': test})
    score = int(result[0])
    if score > best_score:
        best_score = score
        best_inp = test
        print(f"New best: score={score}, input={''.join(chr(b) for b in test)}")

print(f"\nBest random score: {best_score}")

# What's the max possible score?
# Sum all leaf values
import onnx
model = onnx.load(MODEL_PATH)
graph = model.graph

def get_max_leaf(if_node):
    for attr in if_node.attribute:
        if attr.name == 'then_branch':
            for n in attr.g.node:
                if n.op_type == 'If':
                    return get_max_leaf(n)
            # Leaf - find constant
            for n in attr.g.node:
                if n.op_type == 'Constant':
                    for a in n.attribute:
                        if a.name == 'value':
                            val = onnx.numpy_helper.to_array(a.t)
                            if n.output[0] in [o.name for o in attr.g.output]:
                                return int(val)
    return 0

total_max = 0
for node in graph.node:
    if node.op_type == 'If':
        leaf = get_max_leaf(node)
        total_max += leaf
print(f"Max possible score (sum of all leaf weights): {total_max}")
