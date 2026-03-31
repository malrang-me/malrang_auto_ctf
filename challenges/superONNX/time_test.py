#!/usr/bin/env python3
import numpy as np
import onnxruntime as ort
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
sess = ort.InferenceSession(MODEL_PATH)
input_name = sess.get_inputs()[0].name
output_name = sess.get_outputs()[0].name

test = np.full(56, ord('A'), dtype=np.uint8)

# Time 10 evaluations
t0 = time.time()
for i in range(10):
    result = sess.run([output_name], {input_name: test})
t1 = time.time()
print(f"10 evals: {t1-t0:.3f}s -> {(t1-t0)/10:.4f}s each")
print(f"Score for all 'A': {int(result[0])}")

# Per-pass estimate: 95 chars * 56 positions = 5320 evals
per_eval = (t1-t0)/10
print(f"Estimated per pass (95*56=5320 evals): {per_eval*5320:.1f}s = {per_eval*5320/60:.1f}min")
