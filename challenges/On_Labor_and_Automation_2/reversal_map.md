# Reversal Map: On_Labor_and_Automation_2

## Binary Info
- Format: x86-64 ELF PIE, dynamically linked, not stripped
- Size: ~18 KB per round (varies slightly)
- Architecture: x86-64, little-endian
- Symbols: table1, table2, key, main (symbol table present, not stripped)
- Build: PIE executable, GLIBC 2.7/2.2.5/2.34

## Input Vectors
- Service: host8.dreamhack.games:22254
- Protocol: recv base64-encoded ELF, send space-separated integers
- Input format: N integers via scanf("%d"), N = len(key) from symbol table
- Round 1: N=18 integers (key size = 18 bytes)
- Input range: each integer in 0..255 (used as table index)
- Rounds: 50 total; each round has independently randomized table1/table2/key

## Algorithm / Validation Logic

```c
// Pseudocode reconstructed from disassembly at 0x1149
int main() {
    int input[N];                        // N = key.size (18 in round 1)
    for (int i = 0; i <= N-1; i++)
        if (scanf("%d", &input[i]) != 1) return 0;

    for (int i = 0; i <= N-1; i++) {
        int x    = input[i];             // user integer (0..255)
        int t2   = table2[x];            // table2: int[256] lookup
        int t1   = table1[t2];           // table1: int[256] lookup
        char k   = (char)key[i];         // key: byte[N]
        if (t1 != (unsigned char)k)
            return 0;                    // FAIL - no output
    }
    puts("OK");
    return 0;
}
```

Key disassembly trace:
- 0x1195: `cmpl $0x11, -0x4(%rbp)` / `jle 0x115a` - loop bound 0..17 = 18 iters
- 0x11b7: `lea 0x32a2(%rip),%rax` -> table2 at VA 0x4460
- 0x11cb: `lea 0x2e8e(%rip),%rax` -> table1 at VA 0x4060
- 0x11da: `lea 0x2e5f(%rip),%rcx` -> key at VA 0x4040
- 0x11e8: `cmp %eax,%edx` / `je` - comparison table1[table2[x]] == key[i]

## Data Structures (Round 1 Example)

| Symbol | VA     | File Offset | Size  | Type     |
|--------|--------|-------------|-------|----------|
| table1 | 0x4060 | 0x3060      | 1024B | int[256] |
| table2 | 0x4460 | 0x3460      | 1024B | int[256] |
| key    | 0x4040 | 0x3040      | 18B   | byte[18] |

VA -> file offset relationship: va_base = .data_addr - .data_fileoff = 0x4020 - 0x3020 = 0x1000
(Recalculated per binary from section headers)

Round 1 key: [47, 48, 79, 115, 68, 114, 111, 98, 112, 44, 45, 35, 84, 64, 115, 81, 82, 58]
  as ASCII: b'/0OsDrobp,-#T@sQR:'

## Attack Strategy

Brute-force inversion (O(N * 256) per binary):

For each position i in 0..N-1:
  target = key[i]
  for x in 0..255:
    if table1[table2[x]] == target:
      input[i] = x; break

This always succeeds because table1 and table2 are permutation-like lookup tables
covering all 256 values. The composition table1[table2[x]] maps each x to exactly
one value and covers the range of key values.

## Recommended Solver Strategy

```python
# ELF parsing
1. Read .symtab + .strtab -> locate table1/table2/key by name
2. Compute VA->file offset from .data section header
3. Read table1[256] as int32-LE, table2[256] as int32-LE, key[N] as bytes

# Solving
for i in range(N):
    for x in range(256):
        if table1[table2[x]] == key[i]:
            answer[i] = x; break

# Communication
send answer as space-separated integers + newline
```

## Verification

- Round 1 answer: `92 208 230 173 178 141 227 10 235 33 35 43 133 6 173 245 115 250`
- Service confirmed: "Correct! Moving to next round..."
- All 50 rounds solved successfully
- Final service response: "Correct! All challenges completed! You are a reverse engineering master!"

## FLAG

```
INCOGNITO{d7451df9c325e5abd4c05333725c9f21b067a1dd37048f2fa153ea76c0655dfd7ce9876e5e089f498b6a0e207642f7d67656aa5ef0a6b28f949950ffe5836c85}
```
