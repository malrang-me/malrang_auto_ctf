# Recon: On_Labor_and_Automation_2

## Binary Info
- Format: x86-64 ELF PIE, dynamically linked, not stripped
- Size: ~18 KB per round
- Entry: main at 0x1149
- Symbols present: table1, table2, key, main

## Service Protocol
- Host: host8.dreamhack.games:22254
- 50 rounds total
- Each round: server sends "Binary (base64): <b64>" then prompts "Enter the correct input (space-separated integers):"
- Correct answer -> "Correct! Moving to next round..."
- After 50 rounds -> flag

## Input Vectors
- Input format: N space-separated integers (one per key byte)
- Round 1: 18 integers (key size = 18)
- Loop bound from disasm: `cmpl $0x11, -0x4(%rbp)` with `jle` -> i=0..17 inclusive = 18 iterations
- Each integer is read via `scanf("%d", ...)` into int32 array on stack

## Algorithm / Validation Logic

```
// Pseudocode from disassembly at 0x1149
int input[18];
for (i=0; i<=17; i++) scanf("%d", &input[i]);

for (i=0; i<=17; i++) {
    int x = input[i];             // user integer
    int t2 = table2[x];           // table2 is int[256]
    int t1 = table1[t2];          // table1 is int[256]
    char k = key[i];              // key is byte[18]
    if (t1 != k) return 0;        // FAIL
}
puts("OK");
```

## Key Data Structures (Round 1)
- table1: int[256] at VA 0x4060, file offset 0x3060, size=1024 bytes
- table2: int[256] at VA 0x4460, file offset 0x3460, size=1024 bytes
- key: byte[18] at VA 0x4040, file offset 0x3040, size=18 bytes
- Round 1 key bytes: [47, 48, 79, 115, 68, 114, 111, 98, 112, 44, 45, 35, 84, 64, 115, 81, 82, 58]
  as ASCII: b'/0OsDrobp,-#T@sQR:'

## Attack Strategy: Brute-Force Inversion

For each position i:
1. Target = key[i]
2. Search x in 0..255: find x such that table1[table2[x]] == target
3. That x is input[i]

Each search is O(256) = trivial. Total: O(18 * 256) per binary.

## ELF Parsing Notes
- VA to file offset: base = .data_va - .data_fileoff = 0x4020 - 0x3020 = 0x1000
- fileoff = VA - 0x1000 (round 1; may vary per round, recalculate from sections)
- Symbol table (.symtab) gives exact VA and size for table1/table2/key

## Verified: Round 1 Solver Output
- Input: 92 208 230 173 178 141 227 10 235 33 35 43 133 6 173 245 115 250
- Service response: "Correct! Moving to next round..."

## Variables Across Rounds
- Key length (N) may vary - derive from symbol table st_size
- table1/table2 values change each round (randomly generated permutation tables)
- key bytes change each round
- The input count loop bound `0x11` might change if key length changes - but this
  appears fixed for the challenge; verify by checking key.size from symtab

## Recommended Solver Strategy
Parse each ELF:
1. Locate .symtab and .strtab sections
2. Find table1, table2, key symbols -> extract VA and size
3. Convert VA to file offset using .data section anchor
4. Read table1[256], table2[256], key[N]
5. For each key[i]: brute-force search x in 0..255 for table1[table2[x]] == key[i]
6. Send space-separated results

Full automation: connect, receive b64, decode ELF, solve, send answer, loop 50x.

## FLAG (Obtained)
```
INCOGNITO{d7451df9c325e5abd4c05333725c9f21b067a1dd37048f2fa153ea76c0655dfd7ce9876e5e089f498b6a0e207642f7d67656aa5ef0a6b28f949950ffe5836c85}
```
Service response: "Correct! All challenges completed! You are a reverse engineering master!"
