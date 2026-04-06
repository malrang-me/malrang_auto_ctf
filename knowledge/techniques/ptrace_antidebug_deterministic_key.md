# ptrace_antidebug_deterministic_key

## Category
rev

## Description
[Auto-extracted technique — manual enrichment recommended]

## Key Code Pattern

```python
#!/usr/bin/env python3
"""
ptrace_block solver
- Static key -> INIT_1 cumulative sum -> brute-force INIT_2 XOR byte -> AES-128-CBC decrypt
"""
import string
from Crypto.Cipher import AES

# Step 1: Static base key from binary .data @ offset 0x3010
KEY_HEX = "4128194ea57ca14113cf88ac2af0b7da"
key = list(bytes.fromhex(KEY_HEX))

# Step 2: INIT_1 transformation (local_24=0 when not traced)
# key[i+1] = (key[i+1] + 0 + key[i]) & 0xFF  for i in 0..14
for i in range(15):
    key[i + 1] = (key[i + 1] + key[i]) & 0xFF

# Step 3: Read ciphertext
with open("challenges/ptrace_block/out.txt", "rb") as f:
    ciphertext = f.read()

IV = b"\x00" * 16

# Step 4: Brute-force INIT_2 XOR byte (256 candidates)
printable = set(string.printable.encode())

flag = None
for xor_byte in range(256):
    candidate_key = bytes(k ^ xor_byte for k in key)
    cipher = AES.new(candidate_key, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    # Find end of flag (closing brace) and check up to that point
    end = plaintext.find(b"}")
    if plaintext[:3] == b"DH{" and end != -1 and all(b in printable for b in plaintext[:end + 1]):
        # Strip null padding and print
        flag = plaintext.rstrip(b"\x00").rstrip(b"\n").decode("ascii", errors="replace")
        print(f"[+] XOR byte: 0x{xor_byte:02x}")
        print(f"[+] Key: {candidate_key.hex()}")
        print(f"[+] FLAG: {flag}")
        break

if flag is None:
    print("[-] No valid flag found")

```

## When to Use
- [TODO: describe when this technique applies]

## References
- Challenge: ptrace_block
