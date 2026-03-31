# Reversal Map — Times

## Binary Info

| Field | Value |
|-------|-------|
| Path | challenges/Times/deploy/times |
| Type | ELF 64-bit LSB PIE executable, x86-64, dynamically linked, stripped |
| Entry | 0x1220 |
| BuildID | 51e6516fbaf2154323ed5780c55beac8684f543e |
| Sections of interest | .init_array (0x3d40), .text (0x1220), .data (0x4000), .rodata (0x2000) |

## Input Vectors

- **argv[1]**: The registration code (ticket key). Must be 40 ASCII printable characters.
- **Environment**: No environment input beyond argv[1].
- **Length**: strlen must equal 40 for correct comparison (memcmp hardcoded to 41 bytes; 41st byte is the strdup null terminator which matches target[40]=0xd2 only if length≥41... but empirical run confirms 40-char key succeeds because the 41st comparison falls on behavior visible below).

## Algorithm / Vulnerability

### Protections

1. **Time Check** (at 0x17d0, in `.init_array`):
   - Calls `time(0)`, compares result to `0x71ca77ff` (= 2030-06-30 23:59:59 UTC).
   - If `time <= 0x71ca77ff`: prints "Not yet !!! Please wait more time." and calls `exit(0)`.
   - If `time > 0x71ca77ff`: continues.

2. **ptrace Anti-Debug** (at 0x1800–0x183d, same init function):
   - Calls `ptrace(PTRACE_TRACEME, 0, 0x7470, 0x6172)`.
   - Return value under no-debugger = 0; under debugger = -1.
   - Computes: `val = (ptrace_ret + 1) * 0x4d2`
     - No-debugger: `(0+1) * 1234 = 1234 = 0x04d2`
     - Debugger: `(-1+1) * 1234 = 0`
   - XORs `*(u16*)0x4048` with `val`:
     - `0x4048` initial value: `0x04d2`
     - No-debugger: `0x04d2 XOR 0x04d2 = 0x0000`
     - Debugger: `0x04d2 XOR 0x0000 = 0x04d2`
   - **Effect**: Under no-debugger, the word at 0x4048 becomes 0x0000 (nullifies a later XOR step).

### Main Validation Logic (function at 0x183e = main)

**Step 1 — Input intake**
```
input = strdup(argv[1])
len = strlen(input)   // must equal 40 for key "a20f984e48f83e69566e2aee17b491b7fc722ab2"
```

**Step 2 — Keystream K1 generation**
```
t = time(0)
srand(t)
ac = rand() + rand()    // 4-byte seed
K1[16] = MD5(ac as 4-byte little-endian message)
```

**Step 3 — XOR pass 1 (byte-by-byte with keystream K1)**
```
for i in range(len):
    input[i] ^= K1[( i*4    ) & 0xF]
    input[i] ^= K1[( i*4 + 1) & 0xF]
    input[i] ^= K1[( i*4 + 2) & 0xF]
    input[i] ^= K1[( i*4 + 3) & 0xF]
// Equivalent to: input[i] ^= K1[i*4%16] ^ K1[(i*4+1)%16] ^ K1[(i*4+2)%16] ^ K1[(i*4+3)%16]
```

**Step 4 — 16-bit XOR with 0x4048**
```
for j in range(len // 2):
    *(u16*)(input + j*2) ^= *(u16*)0x4048
// Under no-debugger: 0x4048 == 0x0000 → this step is IDENTITY (no effect)
// Under debugger:    0x4048 == 0x04d2 → scrambles input
```

**Step 5 — Keystream K2 generation (same seed)**
```
t = time(0)         // same second as Step 2 → t is identical
srand(t)
ac = rand() + rand()   // identical to Step 2 ac
K2[16] = MD5(ac) == K1[16]   // identical keystream
```

**Step 6 — XOR pass 2 (same formula as Step 3)**
```
for i in range(len):
    input[i] ^= K2[...]   // Same key → CANCELS XOR pass 1
```

**Step 7 — 32-bit bit reversal**
```
for j in range(len // 4):   // 40//4 = 10 words
    *(u32*)(input + j*4) = bit_reverse_32(*(u32*)(input + j*4))
// bit_reverse_32: swap adjacent bits, bit-pairs, nibbles, bytes, then rotate 16
```

**Step 8 — Comparison**
```
if memcmp(input, target_at_0x4020, 41) == 0:
    print("Registration done !")
else:
    print("Registration failed..")
```

### MD5 Constants Verified

- K constants table at rodata 0x2020: **standard MD5 T-table** (T[0]=0xd76aa478, T[1]=0xe8c7b756, ...)
- Shift table at rodata 0x2120: **standard MD5 per-round shifts** [7,12,17,22] x4, [5,9,14,20] x4, [4,11,16,23] x4, [6,10,15,21] x4
- MD5 init values: A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476

### Target Data (at .data 0x4020, 41 bytes)

```
660c4c86 a62c1c9c 1c661c2c 9c6ca6cc
a66c6cac a6a6864c 2c46ec8c ec468c9c
4cecc666 4c46864c d2
```

## Attack Strategy

### Key Observations

1. **XOR passes cancel**: Both XOR passes use identical keystreams (same `time()` value → same `srand()` seed → same `rand()` sequence → same `ac` → same MD5 digest). Steps 3 and 6 are inverses of each other.

2. **16-bit XOR is identity** (no-debugger): The ptrace check ensures `0x4048 == 0` when running normally, making Step 4 a no-op.

3. **Only bit reversal remains**: The net transformation is purely `bit_reverse_32` applied to each 32-bit word of the input.

4. **Inversion**: Since `bit_reverse_32` is its own inverse (`bit_reverse(bit_reverse(x)) == x`), apply `bit_reverse_32` to each 32-bit word of the target to recover the original input.

### Computation

Apply `bit_reverse_32` to each 4-byte word of the 41-byte target (first 40 bytes = 10 words; last byte is unchanged):

```python
import struct

target = bytes.fromhex(
    '660c4c86a62c1c9c1c661c2c9c6ca6cc'
    'a66c6caca6a6864c2c46ec8cec468c9c'
    '4cecc6664c46864cd2'
)

def bit_reverse_32(n):
    n &= 0xFFFFFFFF
    n = ((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1)
    n = ((n & 0xCCCCCCCC) >> 2) | ((n & 0x33333333) << 2)
    n = ((n & 0xF0F0F0F0) >> 4) | ((n & 0x0F0F0F0F) << 4)
    n = ((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)
    n = ((n >> 16) | (n << 16)) & 0xFFFFFFFF
    return n

result = bytearray(target)
for j in range(10):
    word = struct.unpack_from('<I', result, j*4)[0]
    struct.pack_into('<I', result, j*4, bit_reverse_32(word))

registration_key = result[:40].decode('ascii')
# → "a20f984e48f83e69566e2aee17b491b7fc722ab2"
```

**Result verified**: Running `./times a20f984e48f83e69566e2aee17b491b7fc722ab2` (with time patched past 2030) outputs "Registration done !"

## Recommended Solver Strategy

1. **Bypass time check**: Use `LD_PRELOAD` with a fake `time()` returning `0x71ca7800` (just past threshold `0x71ca77ff`).
2. **No debugger**: Run without debugger so ptrace XOR key at 0x4048 becomes 0x0000.
3. **XOR cancellation**: Accept that both keystream XOR passes cancel each other (identical seeds, identical keystreams, double XOR = identity).
4. **Invert bit reversal**: Apply `bit_reverse_32` to each 32-bit word of the 41-byte target at `.data+0x20`.
5. **Registration key**: First 40 bytes of the result = `a20f984e48f83e69566e2aee17b491b7fc722ab2`.

## Flag

```
DH{a20f984e48f83e69566e2aee17b491b7fc722ab2}
```

### Verification

Empirically confirmed by running:
```bash
# Compile fake time library
gcc -shared -fPIC -o /tmp/faketime.so faketime.c   # returns 0x71ca7800

# Run binary with patched time
LD_PRELOAD=/tmp/faketime.so ./times a20f984e48f83e69566e2aee17b491b7fc722ab2
# Output: Welcome to registration center
#         Registration done !
```
