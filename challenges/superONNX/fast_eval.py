#!/usr/bin/env python3
"""
Compile ONNX graph to fast pure-Python evaluator (no numpy per-op).
Use ctypes int32 wrapping only where needed.
"""
import onnx
from onnx import numpy_helper
import numpy as np
import time
import ctypes

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    init_map[init.name] = int(numpy_helper.to_array(init).item())

def sanitize(name):
    return name.replace('.', '_').replace('-', '_')

def i32(val):
    """Convert to signed int32 (Python equivalent)."""
    val = val & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val

def compile_sg(sg, indent=2):
    """Compile subgraph to Python code lines."""
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
                    lines.append(f"{prefix}{v} = {val}")
        elif op == 'Gather':
            idx_name = ins[1]
            # Check local constants first
            found = False
            for n2 in sg.node:
                if n2.op_type == 'Constant' and n2.output[0] == idx_name:
                    for attr in n2.attribute:
                        if attr.name == 'value':
                            idx = int(numpy_helper.to_array(attr.t).item())
                            lines.append(f"{prefix}{v} = I[{idx}]")
                            found = True
            if not found:
                if idx_name in init_map:
                    lines.append(f"{prefix}{v} = I[{init_map[idx_name]}]")
                else:
                    lines.append(f"{prefix}{v} = I[{sanitize(idx_name)}]")
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

            if op == 'Add': lines.append(f"{prefix}{v} = i32({a} + {b})")
            elif op == 'Sub': lines.append(f"{prefix}{v} = i32({a} - {b})")
            elif op == 'Mul': lines.append(f"{prefix}{v} = i32({a} * {b})")
            elif op == 'BitwiseAnd': lines.append(f"{prefix}{v} = {a} & {b}")
            elif op == 'BitwiseOr': lines.append(f"{prefix}{v} = {a} | {b}")
            elif op == 'BitwiseXor': lines.append(f"{prefix}{v} = {a} ^ {b}")
            elif op == 'Less': lines.append(f"{prefix}{v} = {a} < {b}")
            elif op == 'Greater': lines.append(f"{prefix}{v} = {a} > {b}")
            elif op == 'Not': lines.append(f"{prefix}{v} = not {a}")
            elif op == 'Equal': lines.append(f"{prefix}{v} = {a} == {b}")
    return lines

# Compile main graph
print("Compiling...")
code_lines = [
    "def evaluate(I):",
    "  total = 0",
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
                code_lines.append(f"  {v} = {val}")
    elif op == 'Gather':
        a_name = ins[0]
        b_name = ins[1]
        b = str(init_map[b_name]) if b_name in init_map else sanitize(b_name)
        code_lines.append(f"  {v} = I[{b}]")
    else:
        a_name = ins[0]
        b_name = ins[1] if len(ins) > 1 else None
        a = str(init_map[a_name]) if a_name in init_map else sanitize(a_name)
        b = str(init_map[b_name]) if b_name in init_map else sanitize(b_name) if b_name else None

        if op == 'Add': code_lines.append(f"  {v} = i32({a} + {b})")
        elif op == 'Sub': code_lines.append(f"  {v} = i32({a} - {b})")
        elif op == 'Mul': code_lines.append(f"  {v} = i32({a} * {b})")
        elif op == 'BitwiseAnd': code_lines.append(f"  {v} = {a} & {b}")
        elif op == 'BitwiseOr': code_lines.append(f"  {v} = {a} | {b}")
        elif op == 'BitwiseXor': code_lines.append(f"  {v} = {a} ^ {b}")
        elif op == 'Less': code_lines.append(f"  {v} = {a} < {b}")
        elif op == 'Greater': code_lines.append(f"  {v} = {a} > {b}")
        elif op == 'Not': code_lines.append(f"  {v} = not {a}")
        elif op == 'Equal': code_lines.append(f"  {v} = {a} == {b}")

code_lines.append("  return total")
code = '\n'.join(code_lines)

# Write to file for inspection
with open('/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/compiled_func.py', 'w') as f:
    f.write("def i32(val):\n  val = val & 0xFFFFFFFF\n  if val >= 0x80000000: val -= 0x100000000\n  return val\n\n")
    f.write(code)

print(f"Generated {len(code_lines)} lines")

# Compile and execute
exec(compile("def i32(val):\n  val = val & 0xFFFFFFFF\n  if val >= 0x80000000: val -= 0x100000000\n  return val\n\n" + code, '<compiled>', 'exec'))

# Verify
import onnxruntime as ort
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name

for tv in [0, 65, 80, 100, 200, 255]:
    compiled = evaluate(list(range(tv, tv+56)) if tv < 200 else [tv]*56)
    inp_list = list(range(tv, tv+56)) if tv < 200 else [tv]*56
    onnx_s = int(sess.run([oname], {iname: np.array(inp_list, dtype=np.uint8)})[0])
    match = "OK" if compiled == onnx_s else f"FAIL c={compiled}"
    print(f"  test {tv}: onnx={onnx_s} {match}")

# Benchmark
t = time.time()
for _ in range(1000):
    evaluate([65]*56)
e1 = time.time() - t

t = time.time()
for _ in range(100):
    sess.run([oname], {iname: np.array([65]*56, dtype=np.uint8)})
e2 = time.time() - t

print(f"\nSpeed: compiled={1000/e1:.0f}/s, onnx={100/e2:.0f}/s, speedup={e2/e1*10:.1f}x")

# HILL CLIMBING
print("\n=== HILL CLIMBING ===")
best = [80] * 56
best_score = evaluate(best)
print(f"Start: {best_score}")

start = time.time()
for iteration in range(50):
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

    elapsed = time.time() - start
    flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
    print(f"  iter {iteration}: score={best_score}/2563 time={elapsed:.0f}s flag='{flag}'")

    if best_score == 2563 or not improved:
        break

# Verify final with ONNX
final_onnx = int(sess.run([oname], {iname: np.array(best, dtype=np.uint8)})[0])
flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
print(f"\n=== FINAL ===")
print(f"Score (compiled): {best_score}/2563")
print(f"Score (ONNX):     {final_onnx}/2563")
print(f"Flag: {flag}")
