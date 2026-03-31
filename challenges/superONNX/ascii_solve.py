#!/usr/bin/env python3
"""
Hill climb with ASCII-only constraint, starting from HSPACE{ prefix.
"""
import numpy as np
import onnxruntime as ort
import time
import random

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name

def score(inp):
    return int(sess.run([oname], {iname: np.array(inp, dtype=np.uint8)})[0])

# ASCII printable range
CHARS = list(range(32, 127))

# Try multiple starting points
best_overall = None
best_overall_score = 0

for trial in range(5):
    # Random printable start
    if trial == 0:
        # Start with HSPACE{...}
        start = list(b'HSPACE{') + [random.choice(CHARS) for _ in range(48)] + [ord('}')]
    else:
        start = [random.choice(CHARS) for _ in range(56)]

    best = list(start)
    best_score = score(best)
    print(f"\nTrial {trial}: start={best_score}")

    for iteration in range(10):
        improved = False
        for pos in range(56):
            old = best[pos]
            best_v = old
            best_s = best_score
            for v in CHARS:
                if v == old: continue
                best[pos] = v
                s = score(best)
                if s > best_s:
                    best_s = s
                    best_v = v
            best[pos] = best_v
            if best_s > best_score:
                best_score = best_s
                improved = True

        flag = ''.join(chr(b) for b in best)
        print(f"  iter {iteration}: score={best_score} flag='{flag}'")

        if not improved:
            break

    if best_score > best_overall_score:
        best_overall_score = best_score
        best_overall = list(best)

print(f"\n=== BEST RESULT ===")
flag = ''.join(chr(b) for b in best_overall)
print(f"Score: {best_overall_score}/2563")
print(f"Flag: {flag}")
