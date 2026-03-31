#!/usr/bin/env python3
"""
Compile ONNX constraint graph to fast Python function, then hill climb.
"""
import onnx
from onnx import numpy_helper
import numpy as np
import time

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    init_map[init.name] = int(numpy_helper.to_array(init).item())

def compile_subgraph(sg, depth=0):
    """Compile a subgraph to a Python code string."""
    lines = []
    for node in sg.node:
        op = node.op_type
        ins = list(node.input)
        outs = list(node.output)
        v = outs[0].replace('.', '_').replace('-', '_')

        if op == 'Constant':
            for attr in node.attribute:
                if attr.name == 'value':
                    val = int(numpy_helper.to_array(attr.t).item())
                    lines.append(f"  {v} = {val}")

        elif op == 'Gather':
            idx_name = ins[1]
            # Check if it's a known constant
            idx_val = init_map.get(idx_name)
            if idx_val is None:
                # It might be defined in this subgraph
                idx_ref = idx_name.replace('.', '_').replace('-', '_')
                lines.append(f"  {v} = I[{idx_ref}]")
            else:
                lines.append(f"  {v} = I[{idx_val}]")

        elif op == 'If':
            cond = ins[0].replace('.', '_').replace('-', '_')
            lines.append(f"  if {cond}:")
            # then branch
            for attr in node.attribute:
                if attr.name == 'then_branch':
                    then_lines = compile_subgraph(attr.g, depth+1)
                    for l in then_lines:
                        lines.append(f"  {l}")
                    # Find the output value
                    out_name = attr.g.output[0].name.replace('.', '_').replace('-', '_')
                    result_name = outs[0].replace('.', '_').replace('-', '_')
                    lines.append(f"    {result_name} = {out_name}")
            lines.append(f"  else:")
            for attr in node.attribute:
                if attr.name == 'else_branch':
                    else_lines = compile_subgraph(attr.g, depth+1)
                    for l in else_lines:
                        lines.append(f"  {l}")
                    out_name = attr.g.output[0].name.replace('.', '_').replace('-', '_')
                    result_name = outs[0].replace('.', '_').replace('-', '_')
                    lines.append(f"    {result_name} = {out_name}")

        else:
            a = ins[0].replace('.', '_').replace('-', '_') if len(ins) > 0 else None
            b = ins[1].replace('.', '_').replace('-', '_') if len(ins) > 1 else None
            # Check if inputs are init values
            if ins[0] in init_map:
                a = str(init_map[ins[0]])
            if len(ins) > 1 and ins[1] in init_map:
                b = str(init_map[ins[1]])

            if op == 'Add': lines.append(f"  {v} = np.int32(np.int32({a}) + np.int32({b}))")
            elif op == 'Sub': lines.append(f"  {v} = np.int32(np.int32({a}) - np.int32({b}))")
            elif op == 'Mul': lines.append(f"  {v} = np.int32(np.int32({a}) * np.int32({b}))")
            elif op == 'BitwiseAnd': lines.append(f"  {v} = int(np.int32({a}) & np.int32({b}))")
            elif op == 'BitwiseOr': lines.append(f"  {v} = int(np.int32({a}) | np.int32({b}))")
            elif op == 'BitwiseXor': lines.append(f"  {v} = int(np.int32({a}) ^ np.int32({b}))")
            elif op == 'Less': lines.append(f"  {v} = bool(np.int32({a}) < np.int32({b}))")
            elif op == 'Greater': lines.append(f"  {v} = bool(np.int32({a}) > np.int32({b}))")
            elif op == 'Not': lines.append(f"  {v} = not {a}")
            elif op == 'Equal': lines.append(f"  {v} = bool({a} == {b})")

    return lines

# Build the compiled function
print("Compiling ONNX graph to Python...")
code_lines = ["def evaluate(I):", "  I = [np.int32(v) for v in I]", "  total = 0"]

for node in graph.node:
    if node.op_type == 'Cast':
        continue
    if node.op_type in ('Reshape', 'Concat', 'ReduceSum'):
        continue

    if node.op_type == 'If':
        outs = list(node.output)
        v = outs[0].replace('.', '_').replace('-', '_')
        cond = node.input[0].replace('.', '_').replace('-', '_')
        code_lines.append(f"  if {cond}:")

        for attr in node.attribute:
            if attr.name == 'then_branch':
                then_lines = compile_subgraph(attr.g)
                for l in then_lines:
                    code_lines.append(f"  {l}")
                out_name = attr.g.output[0].name.replace('.', '_').replace('-', '_')
                code_lines.append(f"    {v} = {out_name}")

        code_lines.append(f"  else:")
        for attr in node.attribute:
            if attr.name == 'else_branch':
                else_lines = compile_subgraph(attr.g)
                for l in else_lines:
                    code_lines.append(f"  {l}")
                out_name = attr.g.output[0].name.replace('.', '_').replace('-', '_')
                code_lines.append(f"    {v} = {out_name}")

        code_lines.append(f"  total += int({v})")
        continue

    # Regular node
    ins = list(node.input)
    outs = list(node.output)
    v = outs[0].replace('.', '_').replace('-', '_')
    a = ins[0].replace('.', '_').replace('-', '_') if len(ins) > 0 else None
    b = ins[1].replace('.', '_').replace('-', '_') if len(ins) > 1 else None

    if ins[0] in init_map: a = str(init_map[ins[0]])
    if len(ins) > 1 and ins[1] in init_map: b = str(init_map[ins[1]])

    op = node.op_type
    if op == 'Gather': code_lines.append(f"  {v} = I[{b}]")
    elif op == 'Add': code_lines.append(f"  {v} = np.int32(np.int32({a}) + np.int32({b}))")
    elif op == 'Sub': code_lines.append(f"  {v} = np.int32(np.int32({a}) - np.int32({b}))")
    elif op == 'Mul': code_lines.append(f"  {v} = np.int32(np.int32({a}) * np.int32({b}))")
    elif op == 'BitwiseAnd': code_lines.append(f"  {v} = int(np.int32({a}) & np.int32({b}))")
    elif op == 'BitwiseOr': code_lines.append(f"  {v} = int(np.int32({a}) | np.int32({b}))")
    elif op == 'BitwiseXor': code_lines.append(f"  {v} = int(np.int32({a}) ^ np.int32({b}))")
    elif op == 'Less': code_lines.append(f"  {v} = bool(np.int32({a}) < np.int32({b}))")
    elif op == 'Greater': code_lines.append(f"  {v} = bool(np.int32({a}) > np.int32({b}))")
    elif op == 'Not': code_lines.append(f"  {v} = not {a}")
    elif op == 'Equal': code_lines.append(f"  {v} = bool({a} == {b})")
    elif op == 'Constant':
        for attr in node.attribute:
            if attr.name == 'value':
                val = int(numpy_helper.to_array(attr.t).item())
                code_lines.append(f"  {v} = {val}")

code_lines.append("  return total")

code = '\n'.join(code_lines)

# Save compiled code
with open('compiled_eval.py', 'w') as f:
    f.write("import numpy as np\n\n")
    f.write(code)
    f.write("\n")

print(f"Generated {len(code_lines)} lines of code")

# Execute
exec(compile(code, '<compiled>', 'exec'))

# Verify
import onnxruntime as ort
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name

for test_val in [0, 65, 80, 100, 200]:
    inp = [test_val] * 56
    compiled_score = evaluate(inp)
    onnx_score = int(sess.run([oname], {iname: np.array(inp, dtype=np.uint8)})[0])
    match = "OK" if compiled_score == onnx_score else f"MISMATCH compiled={compiled_score}"
    print(f"  All {test_val}: onnx={onnx_score} {match}")

# Benchmark
start = time.time()
for _ in range(1000):
    evaluate([65]*56)
elapsed = time.time() - start
print(f"\nBenchmark: {1000/elapsed:.0f} evals/sec (compiled)")

start = time.time()
for _ in range(100):
    sess.run([oname], {iname: np.array([65]*56, dtype=np.uint8)})
elapsed = time.time() - start
print(f"Benchmark: {100/elapsed:.0f} evals/sec (ONNX)")

# Hill climbing with compiled evaluator
print("\n=== Hill Climbing ===")
best = list(range(56))  # start with something
for i in range(56): best[i] = 80  # start at 80
best_score = evaluate(best)
print(f"Initial: {best_score}")

start = time.time()
for iteration in range(30):
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

print(f"\nFinal score: {best_score}/2563")
flag = ''.join(chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in best)
print(f"Flag: {flag}")
print(f"Bytes: {best}")
