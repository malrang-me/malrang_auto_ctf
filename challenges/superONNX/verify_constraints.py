#!/usr/bin/env python3
"""
Verify constraint extraction by comparing with actual ONNX model evaluation.
Execute each block's constraints manually and compare with model output.
"""
import onnx
from onnx import numpy_helper
import numpy as np
import onnxruntime as ort

MODEL_PATH = "/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf/challenges/superONNX/deploy/for_user/chall.onnx"
model = onnx.load(MODEL_PATH)
graph = model.graph

init_map = {}
for init in graph.initializer:
    arr = numpy_helper.to_array(init)
    init_map[init.name] = int(arr.item())

def eval_subgraph_concrete(sg, inp_i32):
    """Evaluate a subgraph with concrete int32 values. Returns the output value."""
    env = {}

    def get_val(name):
        if name in env: return env[name]
        if name == 'input_i32': return None  # Gather handles this
        return None

    for node in sg.node:
        op = node.op_type
        ins = list(node.input)
        outs = list(node.output)

        if op == 'Constant':
            for attr in node.attribute:
                if attr.name == 'value':
                    env[outs[0]] = int(numpy_helper.to_array(attr.t).item())
            continue

        if op == 'Gather':
            idx = env.get(ins[1])
            if idx is not None:
                env[outs[0]] = inp_i32[idx]
            continue

        if op == 'If':
            cond = env.get(ins[0])
            if cond:
                # Take then branch
                for attr in node.attribute:
                    if attr.name == 'then_branch':
                        result = eval_subgraph_concrete(attr.g, inp_i32)
                        env[outs[0]] = result
            else:
                # Take else branch
                for attr in node.attribute:
                    if attr.name == 'else_branch':
                        result = eval_subgraph_concrete(attr.g, inp_i32)
                        env[outs[0]] = result
            continue

        a = env.get(ins[0]) if len(ins) > 0 else None
        b = env.get(ins[1]) if len(ins) > 1 else None

        if op == 'Add':
            env[outs[0]] = np.int32(np.int32(a) + np.int32(b))
        elif op == 'Sub':
            env[outs[0]] = np.int32(np.int32(a) - np.int32(b))
        elif op == 'Mul':
            env[outs[0]] = np.int32(np.int32(a) * np.int32(b))
        elif op == 'BitwiseAnd':
            env[outs[0]] = int(np.int32(a) & np.int32(b))
        elif op == 'BitwiseOr':
            env[outs[0]] = int(np.int32(a) | np.int32(b))
        elif op == 'BitwiseXor':
            env[outs[0]] = int(np.int32(a) ^ np.int32(b))
        elif op == 'Less':
            env[outs[0]] = bool(np.int32(a) < np.int32(b))
        elif op == 'Greater':
            env[outs[0]] = bool(np.int32(a) > np.int32(b))
        elif op == 'Not':
            env[outs[0]] = not a
        elif op == 'Equal':
            env[outs[0]] = bool(a == b)

    # Return the subgraph's output
    for out in sg.output:
        if out.name in env:
            return env[out.name]
    return 0

def eval_main_graph(inp_uint8):
    """Evaluate the full model graph manually."""
    inp_i32 = [int(np.int32(v)) for v in inp_uint8]
    env = {}

    block_results = []

    def get_val(name):
        if name in env: return env[name]
        if name in init_map: return init_map[name]
        return None

    for node in graph.node:
        op = node.op_type
        ins = list(node.input)
        outs = list(node.output)

        if op == 'Cast':
            env['input_i32'] = inp_i32
            continue

        if op in ('Reshape', 'Concat', 'ReduceSum'):
            continue

        if op == 'If':
            cond = get_val(ins[0])
            if cond:
                for attr in node.attribute:
                    if attr.name == 'then_branch':
                        result = eval_subgraph_concrete(attr.g, inp_i32)
                        env[outs[0]] = result
            else:
                for attr in node.attribute:
                    if attr.name == 'else_branch':
                        result = eval_subgraph_concrete(attr.g, inp_i32)
                        env[outs[0]] = result
            block_results.append(int(env[outs[0]]))
            continue

        if op == 'Constant':
            for attr in node.attribute:
                if attr.name == 'value':
                    env[outs[0]] = int(numpy_helper.to_array(attr.t).item())
            continue

        if op == 'Gather':
            idx = get_val(ins[1])
            if idx is not None:
                env[outs[0]] = inp_i32[idx]
            continue

        a = get_val(ins[0]) if len(ins) > 0 else None
        b = get_val(ins[1]) if len(ins) > 1 else None

        if op == 'Add':
            env[outs[0]] = int(np.int32(np.int32(a) + np.int32(b)))
        elif op == 'Sub':
            env[outs[0]] = int(np.int32(np.int32(a) - np.int32(b)))
        elif op == 'Mul':
            env[outs[0]] = int(np.int32(np.int32(a) * np.int32(b)))
        elif op == 'BitwiseAnd':
            env[outs[0]] = int(np.int32(a) & np.int32(b))
        elif op == 'BitwiseOr':
            env[outs[0]] = int(np.int32(a) | np.int32(b))
        elif op == 'BitwiseXor':
            env[outs[0]] = int(np.int32(a) ^ np.int32(b))
        elif op == 'Less':
            env[outs[0]] = bool(np.int32(a) < np.int32(b))
        elif op == 'Greater':
            env[outs[0]] = bool(np.int32(a) > np.int32(b))
        elif op == 'Not':
            env[outs[0]] = not a
        elif op == 'Equal':
            env[outs[0]] = bool(a == b)

    return block_results, sum(block_results)

# Test with all-A input
test_input = np.array([65]*56, dtype=np.uint8)
block_results, total = eval_main_graph(test_input)
print(f"Manual eval (all A): total={total}")

# Compare with ONNX runtime
sess = ort.InferenceSession(MODEL_PATH)
iname = sess.get_inputs()[0].name
oname = sess.get_outputs()[0].name
onnx_score = int(sess.run([oname], {iname: test_input})[0])
print(f"ONNX runtime (all A): score={onnx_score}")
print(f"Match: {total == onnx_score}")

if total != onnx_score:
    print(f"MISMATCH! Manual={total}, ONNX={onnx_score}")
    print(f"Block results (first 20): {block_results[:20]}")
    print(f"Non-zero blocks: {sum(1 for x in block_results if x > 0)}")

# Test with more inputs
for test_val in [0, 80, 100, 200]:
    test = np.full(56, test_val, dtype=np.uint8)
    br, manual_total = eval_main_graph(test)
    onnx_total = int(sess.run([oname], {iname: test})[0])
    match = "OK" if manual_total == onnx_total else f"MISMATCH manual={manual_total}"
    print(f"All {test_val}: onnx={onnx_total} {match}")
