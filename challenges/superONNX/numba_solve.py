#!/usr/bin/env python3
"""
Numba JIT-compiled scorer for superONNX.
Compile the constraint graph to a numba-compatible function.
"""
import onnx
from onnx import numpy_helper
import numpy as np
import numba
from numba import njit, int32, uint8
import time
import random

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    init_map[init.name] = int(numpy_helper.to_array(init).item())

def sanitize(name):
    return name.replace('.', '_').replace('-', '_')

def compile_sg(sg, indent=2):
    prefix = ' ' * indent
    lines = []
    for node in sg.node:
        op = node.op_type
        ins = list(node.input)
        outs = list(node.output)
        v = sanitize(outs[0])
        if op == 'Constant':
            for attr in node.attribute:
                if attr.name == 'value':
                    val = int(numpy_helper.to_array(attr.t).item())
                    lines.append(f"{prefix}{v} = numba.int32({val})")
        elif op == 'Gather':
            idx_name = ins[1]
            found = False
            for n2 in sg.node:
                if n2.op_type == 'Constant' and n2.output[0] == idx_name:
                    for attr in n2.attribute:
                        if attr.name == 'value':
                            idx = int(numpy_helper.to_array(attr.t).item())
                            lines.append(f"{prefix}{v} = x[{idx}]")
                            found = True
            if not found:
                if idx_name in init_map:
                    lines.append(f"{prefix}{v} = x[{init_map[idx_name]}]")
                else:
                    lines.append(f"{prefix}{v} = x[{sanitize(idx_name)}]")
        elif op == 'If':
            cond = sanitize(ins[0])
            result = sanitize(outs[0])
            lines.append(f"{prefix}if {cond}:")
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    lines.extend(compile_sg(attr.g, indent+2))
                    out_name = sanitize(attr.g.output[0].name)
                    lines.append(f"{prefix}  {result} = {out_name}")
            lines.append(f"{prefix}else:")
            for attr in node.attribute:
                if attr.name == 'else_branch':
                    lines.extend(compile_sg(attr.g, indent+2))
                    out_name = sanitize(attr.g.output[0].name)
                    lines.append(f"{prefix}  {result} = {out_name}")
        else:
            a_name = ins[0] if len(ins) > 0 else None
            b_name = ins[1] if len(ins) > 1 else None
            a = str(init_map[a_name]) if a_name in init_map else sanitize(a_name) if a_name else None
            b = str(init_map[b_name]) if b_name in init_map else sanitize(b_name) if b_name else None
            # Use numba.int32 for arithmetic to handle overflow
            if op == 'Add': lines.append(f"{prefix}{v} = numba.int32(numba.int32({a}) + numba.int32({b}))")
            elif op == 'Sub': lines.append(f"{prefix}{v} = numba.int32(numba.int32({a}) - numba.int32({b}))")
            elif op == 'Mul': lines.append(f"{prefix}{v} = numba.int32(numba.int32({a}) * numba.int32({b}))")
            elif op == 'BitwiseAnd': lines.append(f"{prefix}{v} = numba.int32({a}) & numba.int32({b})")
            elif op == 'BitwiseOr': lines.append(f"{prefix}{v} = numba.int32({a}) | numba.int32({b})")
            elif op == 'BitwiseXor': lines.append(f"{prefix}{v} = numba.int32({a}) ^ numba.int32({b})")
            elif op == 'Less': lines.append(f"{prefix}{v} = numba.int32({a}) < numba.int32({b})")
            elif op == 'Greater': lines.append(f"{prefix}{v} = numba.int32({a}) > numba.int32({b})")
            elif op == 'Not': lines.append(f"{prefix}{v} = not {a}")
            elif op == 'Equal': lines.append(f"{prefix}{v} = numba.int32({a}) == numba.int32({b})")
    return lines

# Compile main graph
print("Compiling ONNX to numba function...")
code_lines = [
    "@njit(cache=True)",
    "def evaluate(x):",
    "  total = numba.int32(0)",
]

for node in graph.node:
    if node.op_type in ('Cast', 'Reshape', 'Concat', 'ReduceSum'):
        continue
    op = node.op_type
    ins = list(node.input)
    outs = list(node.output)
    v = sanitize(outs[0])

    if op == 'If':
        cond = sanitize(ins[0])
        code_lines.append(f"  if {cond}:")
        for attr in node.attribute:
            if attr.name == 'then_branch':
                code_lines.extend(compile_sg(attr.g, 4))
                out_name = sanitize(attr.g.output[0].name)
                code_lines.append(f"    {v} = {out_name}")
        code_lines.append(f"  else:")
        for attr in node.attribute:
            if attr.name == 'else_branch':
                code_lines.extend(compile_sg(attr.g, 4))
                out_name = sanitize(attr.g.output[0].name)
                code_lines.append(f"    {v} = {out_name}")
        code_lines.append(f"  total += {v}")
    elif op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = int(numpy_helper.to_array(attr.t).item())
                code_lines.append(f"  {v} = numba.int32({val})")
    elif op == 'Gather':
        b_name = ins[1]
        b = str(init_map[b_name]) if b_name in init_map else sanitize(b_name)
        code_lines.append(f"  {v} = x[{b}]")
    else:
        a_name = ins[0]
        b_name = ins[1] if len(ins) > 1 else None
        a = str(init_map[a_name]) if a_name in init_map else sanitize(a_name)
        b = str(init_map[b_name]) if b_name in init_map else sanitize(b_name) if b_name else None
        if op == 'Add': code_lines.append(f"  {v} = numba.int32(numba.int32({a}) + numba.int32({b}))")
        elif op == 'Sub': code_lines.append(f"  {v} = numba.int32(numba.int32({a}) - numba.int32({b}))")
        elif op == 'Mul': code_lines.append(f"  {v} = numba.int32(numba.int32({a}) * numba.int32({b}))")
        elif op == 'BitwiseAnd': code_lines.append(f"  {v} = numba.int32({a}) & numba.int32({b})")
        elif op == 'BitwiseOr': code_lines.append(f"  {v} = numba.int32({a}) | numba.int32({b})")
        elif op == 'BitwiseXor': code_lines.append(f"  {v} = numba.int32({a}) ^ numba.int32({b})")
        elif op == 'Less': code_lines.append(f"  {v} = numba.int32({a}) < numba.int32({b})")
        elif op == 'Greater': code_lines.append(f"  {v} = numba.int32({a}) > numba.int32({b})")
        elif op == 'Not': code_lines.append(f"  {v} = not {a}")
        elif op == 'Equal': code_lines.append(f"  {v} = numba.int32({a}) == numba.int32({b})")

code_lines.append("  return total")
code = '\n'.join(code_lines)

print(f"Generated {len(code_lines)} lines")

# Execute the code to define the function
exec(compile(code, '<numba_eval>', 'exec'))

# Warm up JIT
print("JIT compiling (first call)...")
x_test = np.array([65]*56, dtype=np.int32)
t = time.time()
result = evaluate(x_test)
print(f"JIT warmup: {time.time()-t:.1f}s, result={result}")

# Verify
import onnxruntime as ort
sess = ort.InferenceSession(MODEL_PATH)
onnx_result = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: np.array([65]*56, dtype=np.uint8)})[0])
print(f"ONNX result: {onnx_result}")
print(f"Match: {result == onnx_result}")

# Benchmark
print("Benchmarking...")
t = time.time()
for _ in range(100000):
    evaluate(x_test)
elapsed = time.time() - t
print(f"Speed: {100000/elapsed:.0f} evals/sec")

# Hill climbing with JIT scorer
print("\n=== HILL CLIMBING ===")
CHARS = list(range(32, 127))

best_global = None
best_global_score = 0
start = time.time()

for trial in range(20):
    if trial == 0:
        best = np.array(list(b'HSPACE{') + [80]*48 + [ord('}')], dtype=np.int32)
    else:
        best = np.array([random.choice(CHARS) for _ in range(56)], dtype=np.int32)

    best_score = evaluate(best)

    for iteration in range(20):
        improved = False
        for pos in range(56):
            old = best[pos]
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
        flag = ''.join(chr(b) for b in best_global)
        elapsed = time.time() - start
        print(f"  T{trial}: score={best_global_score}/2563 ({elapsed:.0f}s) flag='{flag}'")

# Full-range refinement
print("\n=== Full range refinement ===")
best = best_global.copy()
best_score = best_global_score
for iteration in range(5):
    improved = False
    for pos in range(56):
        old = best[pos]
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

# Final verify
onnx_final = int(sess.run([sess.get_outputs()[0].name], {sess.get_inputs()[0].name: np.array(best, dtype=np.uint8)})[0])
print(f"\nFinal ONNX verification: {onnx_final}/2563")
print(f"Flag: {''.join(chr(int(b)) if 32 <= b <= 126 else f'.{int(b):02x}' for b in best)}")
