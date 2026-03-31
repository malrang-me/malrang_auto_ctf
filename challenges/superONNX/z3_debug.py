#!/usr/bin/env python3
"""Debug: test constraints one block at a time to find issues."""
import onnx
from onnx import numpy_helper
from z3 import *
import numpy as np
import onnxruntime as ort
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

# First, let's see what happens with the known best candidate
sess = ort.InferenceSession(MODEL_PATH)
input_name = sess.get_inputs()[0].name
output_name = sess.get_outputs()[0].name

# Test with HSPACE prefix
test = np.array([ord(c) for c in 'HSPACE{' + 'A'*48 + '}'], dtype=np.uint8)
score = int(sess.run([output_name], {input_name: test})[0])
print(f"HSPACE{{A*48}}: score={score}/2563")

# Test all A's
test2 = np.array([ord('A')]*56, dtype=np.uint8)
score2 = int(sess.run([output_name], {input_name: test2})[0])
print(f"A*56: score={score2}/2563")

# Test with zeros
test3 = np.zeros(56, dtype=np.uint8)
score3 = int(sess.run([output_name], {input_name: test3})[0])
print(f"0*56: score={score3}/2563")

# Test with 255s
test4 = np.full(56, 255, dtype=np.uint8)
score4 = int(sess.run([output_name], {input_name: test4})[0])
print(f"255*56: score={score4}/2563")

# Check input shape
print(f"\nInput shape: {sess.get_inputs()[0].shape}")
print(f"Input type: {sess.get_inputs()[0].type}")
print(f"Output shape: {sess.get_outputs()[0].shape}")
print(f"Output type: {sess.get_outputs()[0].type}")

# Check: does the model accept int32 input or uint8?
test5 = np.array([65]*56, dtype=np.int32)
try:
    score5 = int(sess.run([output_name], {input_name: test5})[0])
    print(f"int32 A*56: score={score5}")
except Exception as e:
    print(f"int32 failed: {e}")

# Let's trace first block manually to see if my Z3 encoding is correct
print("\n=== MANUAL TRACE OF BLOCK 0 ===")
init_values = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_values[init.name] = int(arr.item())

# Block 0 pre-If nodes:
# Gather(input_i32, idx_1=3) -> inp_2  => input[3]
# Gather(input_i32, idx_3=26) -> inp_4  => input[26]
# Add(inp_2, inp_4) -> add_5  => input[3] + input[26]
# Gather(input_i32, idx_6=32) -> inp_7  => input[32]
# BitwiseAnd(add_5, inp_7) -> band_8  => (input[3]+input[26]) & input[32]
# Gather(input_i32, idx_9=9) -> inp_10  => input[9]
# Gather(input_i32, idx_11=25) -> inp_12  => input[25]
# Add(inp_10, inp_12) -> add_13  => input[9] + input[25]
# Gather(input_i32, idx_14=28) -> inp_15  => input[28]
# Sub(add_13, inp_15) -> sub_16  => (input[9]+input[25]) - input[28]
# BitwiseAnd(sub_16, mask_17=255) -> m8_18  => ((input[9]+input[25])-input[28]) & 255
# Less(band_8, m8_18) -> lt_19

# For test='A'*56 (all 65):
x = [65]*56  # all 'A'
add_5 = x[3] + x[26]  # 130
band_8 = add_5 & x[32]  # 130 & 65 = 0
add_13 = x[9] + x[25]  # 130
sub_16 = add_13 - x[28]  # 130 - 65 = 65
m8_18 = sub_16 & 255  # 65
lt_19 = band_8 < m8_18  # 0 < 65 = True
print(f"Block 0 outer condition (A*56): band_8={band_8}, m8_18={m8_18}, lt_19={lt_19}")

# Then branch level 1:
# Gather idx=15 -> input[15]=65, Gather idx=16 -> input[16]=65
# Sub(65, 65) -> 0
# Gather idx=18 -> input[18]=65
# BitwiseAnd(0, 65) -> 0
# Greater(0, 38) -> False
# Not(False) -> True (i.e., 0 <= 38)
sub_5 = x[15] - x[16]  # 0
band_8_t1 = sub_5 & x[18]  # 0 & 65 = 0
gt_10 = 0 > 38  # False
le_11 = not gt_10  # True
print(f"Block 0 then-level-1: sub={sub_5}, band={band_8_t1}, gt={gt_10}, le={le_11}")

# Check if input is uint8 and Cast to int32
print("\n=== CHECK CAST BEHAVIOR ===")
# In the ONNX graph, Cast(input) -> input_i32
# So input is uint8, cast to int32
# For uint8 input 65, int32 is 65 - no issue for values 0-255

# Now: what about values > 127? In uint8, 200 -> in int32 still 200 (not -56)
# The Cast from uint8 to int32 should preserve the unsigned value

# Let's check what input types the model expects
for inp_info in sess.get_inputs():
    print(f"Input '{inp_info.name}': type={inp_info.type}, shape={inp_info.shape}")

# Try with varying inputs to understand constraint sensitivity
print("\n=== CONSTRAINT SENSITIVITY ===")
for val in [0, 32, 48, 65, 80, 97, 100, 110, 120, 126, 200, 255]:
    t = np.full(56, val, dtype=np.uint8)
    s = int(sess.run([output_name], {input_name: t})[0])
    print(f"  all {val}: score={s}")
