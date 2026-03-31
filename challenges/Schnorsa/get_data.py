#!/usr/bin/env python3
"""Get 4 signatures from Schnorsa server and save data"""
import os, json
from pwn import *
import gmpy2

HOST = os.getenv("HOST", "host8.dreamhack.games")
PORT = int(os.getenv("PORT", "17350"))

io = remote(HOST, PORT)

line = io.recvline().decode().strip()
print(line[:80])
e, phi, n, y = eval(line.split("Pubkey: ")[1])
nb = 1024

# Factor n from phi
s_val = n - phi + 1
disc = gmpy2.isqrt(s_val*s_val - 4*n)
p = int((s_val + disc) // 2)
q = int((s_val - disc) // 2)
assert p * q == n
d = int(gmpy2.invert(e, phi))

print(f"p bits={p.bit_length()}, q bits={q.bit_length()}")

sigs = []
for msg_val in range(4):
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"m: ", str(msg_val).encode())
    sig_line = io.recvline().decode().strip()
    r, s = eval(sig_line.split("Sig: ")[1])
    rd = pow(r, d, n)
    inv_2nb = pow(2, -nb, n)
    t = ((rd - msg_val) * inv_2nb) % n
    sigs.append({"r": r, "s": s, "msg": msg_val, "t": t})
    print(f"Sig {msg_val}: r={r.bit_length()}b s={s.bit_length()}b t={t.bit_length()}b")

# Save
data = {
    "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d, "y": y,
    "g": 2, "nb": nb, "sigs": sigs,
    "host": HOST, "port": PORT
}

with open("challenge_data.json", "w") as f:
    json.dump(data, f, default=str)

# Also save as Python for easy import
with open("data4.py", "w") as f:
    f.write(f"p = {p}\n")
    f.write(f"q = {q}\n")
    f.write(f"n = {n}\n")
    f.write(f"phi = {phi}\n")
    f.write(f"e = {e}\n")
    f.write(f"d = {d}\n")
    f.write(f"y = {y}\n")
    f.write(f"nb = {nb}\n")
    f.write(f"g = 2\n\n")
    for i, sig in enumerate(sigs):
        f.write(f"r{i+1} = {sig['r']}\n")
        f.write(f"s{i+1} = {sig['s']}\n")
        f.write(f"t{i+1} = {sig['t']}\n\n")

print("Data saved. Connection still open (1 interaction left).")
print("Keeping connection for submit...")

# Keep connection alive for manual submit
import time
time.sleep(1)

# Read from stdin for x submission
try:
    x_val = input("Enter x to submit (or 'q' to quit): ").strip()
    if x_val != 'q':
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"x: ", x_val.encode())
        result = io.recvall(timeout=5).decode()
        print(result)
except:
    pass

io.close()
