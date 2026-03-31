#!/usr/bin/env python3
"""Fast hill climbing solver with full byte range 0-255."""
import numpy as np
import onnxruntime as ort
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name

def score(inp):
    return int(sess.run([oname], {iname: inp})[0])

# Phase 1: Find good starting point with random search
print("=== Phase 1: Random search ===")
np.random.seed(int(time.time()))
best = np.zeros(56, dtype=np.uint8)
best_score = 0

for i in range(5000):
    t = np.random.randint(0, 256, 56, dtype=np.uint8)
    s = score(t)
    if s > best_score:
        best_score = s
        best = t.copy()
        if i % 100 == 0 or s > 500:
            print(f"  trial {i}: score={s}")

print(f"Best random: {best_score}")

# Phase 2: Greedy hill climbing (full 0-255)
print("\n=== Phase 2: Hill climbing ===")
start = time.time()
for iteration in range(20):
    improved = False
    for pos in range(56):
        old = int(best[pos])
        best_local = old
        best_s = best_score

        for v in range(256):
            if v == old: continue
            best[pos] = v
            s = score(best)
            if s > best_s:
                best_s = s
                best_local = v

        best[pos] = best_local
        if best_s > best_score:
            best_score = best_s
            improved = True

    elapsed = time.time() - start
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
    print(f"  iter {iteration}: score={best_score}/2563 time={elapsed:.0f}s flag='{flag}'")

    if best_score == 2563:
        print("*** PERFECT SCORE ***")
        break
    if not improved:
        print("  No improvement, trying random perturbation...")
        # Random restart from current best
        perturbed = best.copy()
        for _ in range(3):
            pos = np.random.randint(0, 56)
            perturbed[pos] = np.random.randint(0, 256)
        s = score(perturbed)
        if s > best_score - 50:  # accept if not too much worse
            best = perturbed
            best_score = s

print(f"\n=== RESULT ===")
flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
print(f"Score: {best_score}/2563")
print(f"Flag: {flag}")
print(f"Bytes: {list(best)}")
