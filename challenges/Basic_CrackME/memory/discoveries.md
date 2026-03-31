# Basic CrackME - Discoveries

## Challenge
- AutoIt script with embedded x86 shellcode (CRC32 computation)
- 32-character input validated character-by-character
- Each character's CRC32 is XORed with a key and compared to hardcoded FLAG array

## Shellcode Analysis
- x86 stdcall function at the shellcode bytes
- Builds standard CRC32 lookup table (polynomial 0xEDB88320)
- Computes CRC32 of input data with init value 0xFFFFFFFF
- Applies final NOT to result
- This is standard CRC32, verified against Python's `binascii.crc32`

## Key Finding
- The script states `BitXOR(3735929054, $CALC)` where 3735929054 = 0xDEADC0DE
- However, frequency analysis reveals the actual effective XOR key is **0x7F** (127)
- This discrepancy may be due to AutoIt's internal number handling or a challenge quirk
- With XOR key 0x7F, all 32 FLAG values map to CRC32 of printable ASCII characters

## Flag
```
DH{Profitez_des_analyses_AUTOIT}
```

## Technique
- Brute-force frequency analysis: for each possible XOR key, count how many FLAG positions
  map to valid CRC32 values of printable ASCII characters
- The correct key produces 32/32 matches with a coherent DH{...} flag
