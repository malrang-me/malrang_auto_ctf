#!/usr/bin/env python3
"""
1-Weight Overwrite solver
Strategy: Gradient-guided search for the single most impactful weight change.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import base64
import struct
import socket
import re
import sys
import os
import time
import fnmatch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'deploy', 'for_user'))
from model import MobileNetMNIST

HOST = '3.34.9.87'
PORT = 9999
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'deploy', 'for_user', 'model.pt')
CHECKPOINT = None

def is_banned(name, banned_layers):
    for pattern in banned_layers:
        if fnmatch.fnmatch(name, pattern) or name == pattern:
            return True
        if pattern.endswith('.*') and name.startswith(pattern[:-2] + '.'):
            return True
    return False

def load_model():
    global CHECKPOINT
    if CHECKPOINT is None:
        CHECKPOINT = torch.load(MODEL_PATH, map_location='cpu', weights_only=False)
    model = MobileNetMNIST()
    model.load_state_dict(CHECKPOINT['state_dict'])
    model.eval()
    return model

def decode_image(b64_str):
    raw = base64.b64decode(b64_str)
    floats = struct.unpack(f'{len(raw)//4}f', raw)
    return torch.tensor(floats, dtype=torch.float32).reshape(1, 1, 28, 28)

def find_best_weight(model, img, target_label, predicted_label, banned_layers, value_range):
    vmin, vmax = value_range

    for p in model.parameters():
        p.requires_grad_(True)

    logits = model(img)
    loss = logits[0, target_label] - logits[0, predicted_label]
    loss.backward()

    candidates = []
    for name, param in model.named_parameters():
        if is_banned(name, banned_layers):
            continue
        if param.grad is None:
            continue
        grad = param.grad.view(-1).detach().numpy()
        vals = param.data.view(-1).detach().numpy()

        for i in range(len(grad)):
            g = grad[i]
            v = vals[i]
            s_max = g * (vmax - v)
            s_min = g * (vmin - v)
            if s_max >= s_min:
                best_s, best_v = s_max, vmax
            else:
                best_s, best_v = s_min, vmin
            if best_s > 0:
                candidates.append((best_s, name, i, best_v))

    candidates.sort(key=lambda x: -x[0])

    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)

    for score, name, idx, new_val in candidates[:300]:
        param = dict(model.named_parameters())[name]
        flat = param.data.view(-1)
        old_val = flat[idx].item()
        flat[idx] = new_val

        with torch.no_grad():
            new_logits = model(img)[0].numpy()
        flat[idx] = old_val

        if np.argmax(new_logits) == target_label:
            margin = new_logits[target_label] - np.partition(new_logits, -2)[-2]
            return (name, idx, new_val), margin

    return None, -1

class Connection:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        self.sock.connect((host, port))
        self.buf = ''

    def recv_until(self, marker, timeout=30):
        deadline = time.time() + timeout
        while marker not in self.buf:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            self.sock.settimeout(max(remaining, 0.1))
            try:
                data = self.sock.recv(8192)
                if not data:
                    break
                self.buf += data.decode(errors='replace')
            except socket.timeout:
                break
        if marker in self.buf:
            idx = self.buf.index(marker) + len(marker)
            result = self.buf[:idx]
            self.buf = self.buf[idx:]
            return result
        result = self.buf
        self.buf = ''
        return result

    def send(self, data):
        self.sock.sendall(data.encode())

    def close(self):
        self.sock.close()

def main():
    print("[*] Loading model...")
    _ = load_model()

    print(f"[*] Connecting to {HOST}:{PORT}...")
    conn = Connection(HOST, PORT)

    for round_num in range(1, 101):
        # Wait for the round prompt
        data = conn.recv_until('Send your answer as three lines: layer_name, index, value\n', timeout=15)

        # Check for flag
        fm = re.search(r'(hspace\{[^}]+\})', data, re.IGNORECASE)
        if fm:
            print(f"\n{'='*60}")
            print(f"FLAG: {fm.group(1)}")
            print(f"{'='*60}")
            conn.close()
            return

        if 'Round' not in data:
            print(f"Unexpected data (no Round):")
            print(data[:500])
            break

        print(f"\n[Round {round_num}/100]", end=' ')

        # Parse
        banned_match = re.search(r'Banned layers:\s*(.*)', data)
        banned_str = banned_match.group(1).strip() if banned_match else ''
        banned_layers = set()
        if banned_str and banned_str != '(none)':
            banned_layers = set(b.strip() for b in banned_str.split(','))

        range_match = re.search(r'Value range:\s*\[([^,]+),\s*([^\]]+)\]', data)
        vmin, vmax = (float(range_match.group(1)), float(range_match.group(2))) if range_match else (-2.0, 2.0)

        img_match = re.search(r'Image \(base64.*?\):\s*(\S+)', data)
        if not img_match:
            print("Can't parse image!")
            break
        img = decode_image(img_match.group(1))

        target_label = int(re.search(r'Target label:\s*(\d+)', data).group(1))
        predicted_label = int(re.search(r'Original prediction:\s*(\d+)', data).group(1))
        print(f"Pred={predicted_label}->Tgt={target_label} ban={banned_layers or 'none'} range=[{vmin},{vmax}]")

        model = load_model()
        t0 = time.time()
        answer, margin = find_best_weight(model, img, target_label, predicted_label,
                                           banned_layers, (vmin, vmax))

        if answer is None:
            print("  ERROR: No solution found!")
            break

        layer_name, idx, value = answer
        print(f"  {layer_name}[{idx}]={value:.4f} margin={margin:.2f} ({time.time()-t0:.1f}s)")

        conn.send(f"{layer_name}\n{idx}\n{value}\n")

        # Wait for result
        result = conn.recv_until('\n', timeout=10)
        # Read remaining lines until next round or flag
        while result and not result.endswith('passed.\n') and 'FAIL' not in result and 'hspace{' not in result.lower():
            more = conn.recv_until('\n', timeout=5)
            if not more:
                break
            result += more

        # Print server response (compact)
        for line in result.strip().split('\n'):
            l = line.strip()
            if l:
                print(f"  > {l}")

        fm2 = re.search(r'(hspace\{[^}]+\})', result, re.IGNORECASE)
        if fm2:
            print(f"\n{'='*60}")
            print(f"FLAG: {fm2.group(1)}")
            print(f"{'='*60}")
            conn.close()
            return

        if 'FAIL' in result:
            print(f"\n  FAILED at round {round_num}")
            break

    # After all 100 rounds, check for flag
    remaining = conn.recv_until('}\n', timeout=10)
    print(remaining)
    fm3 = re.search(r'(hspace\{[^}]+\})', remaining, re.IGNORECASE)
    if fm3:
        print(f"\nFLAG: {fm3.group(1)}")

    conn.close()

if __name__ == '__main__':
    main()
