#!/usr/bin/env python3
"""Run JIT-compiled solver."""
import numpy as np
import time
import random
import sys

print("Loading JIT module (first call will compile)...")
sys.path.insert(0, '/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX')
from jit_eval import evaluate

# Warm up
t = time.time()
x = np.array([65]*56, dtype=np.int32)
r = evaluate(x)
print(f"JIT compile: {time.time()-t:.1f}s, result={r}")

# Verify
import onnxruntime as ort
sess = ort.InferenceSession("/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx")
onnx_r = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: np.array([65]*56, dtype=np.uint8)})[0])
print(f"ONNX: {onnx_r}, Match: {r == onnx_r}")

# Benchmark
t = time.time()
for _ in range(100000):
    evaluate(x)
elapsed = time.time() - t
print(f"Speed: {100000/elapsed:.0f} evals/sec")

# HILL CLIMBING
print("\n=== HILL CLIMBING ===")
CHARS = list(range(32, 127))
best_global = None
best_global_score = 0
start = time.time()

for trial in range(30):
    if time.time() - start > 480:  # 8 min
        break

    if trial == 0:
        best = np.array(list(b'HSPACE{') + [80]*48 + [ord('}')], dtype=np.int32)
    else:
        best = np.array([random.choice(CHARS) for _ in range(56)], dtype=np.int32)

    best_score = evaluate(best)
    for iteration in range(20):
        improved = False
        for pos in range(56):
            old = int(best[pos])
            best_v = old
            best_s = best_score
            for v in CHARS:
                if v == old: continue
                best[pos] = v
                s = evaluate(best)
                if s > best_s:
                    best_s = s
                    best_v = v
            best[pos] = best_v
            if best_s > best_score:
                best_score = best_s
                improved = True
        if not improved:
            break

    if best_score > best_global_score:
        best_global_score = best_score
        best_global = best.copy()
        flag = ''.join(chr(int(b)) for b in best_global)
        print(f"  T{trial}: score={best_global_score}/2563 ({time.time()-start:.0f}s) flag='{flag}'")

# Full range refinement
print("\n=== Full range ===")
best = best_global.copy()
best_score = best_global_score
for iteration in range(5):
    improved = False
    for pos in range(56):
        old = int(best[pos])
        best_v = old
        best_s = best_score
        for v in range(256):
            if v == old: continue
            best[pos] = v
            s = evaluate(best)
            if s > best_s:
                best_s = s
                best_v = v
        best[pos] = best_v
        if best_s > best_score:
            best_score = best_s
            improved = True
    flag = ''.join(chr(int(b)) if 32 <= b <= 126 else f'\\x{int(b):02x}' for b in best)
    print(f"  iter {iteration}: score={best_score}/2563 flag='{flag}'")
    if not improved:
        break

onnx_final = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: np.array(best, dtype=np.uint8)})[0])
print(f"\nONNX verify: {onnx_final}/2563")
flag = ''.join(chr(int(b)) if 32 <= b <= 126 else f'\\x{int(b):02x}' for b in best)
print(f"Flag: {flag}")
print(f"Bytes: {[int(b) for b in best]}")
