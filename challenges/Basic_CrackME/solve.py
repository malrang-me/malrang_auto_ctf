#!/usr/bin/env python3
"""
Basic CrackME solver

The AutoIt script:
1. Computes CRC32 of each character (standard CRC32, polynomial 0xEDB88320)
2. XORs the result with a key
3. Compares to FLAG[i]

By frequency analysis, the XOR key that maps all FLAG values to CRC32
of printable ASCII (producing a DH{...} flag) is 0x7F.
"""
import binascii

FLAG = [0, 2746444411, 2852464208, 366298950, 3110714886, 1812594658, 252678971,
        1993550751, 3865851406, 2238339799, 4024072741, 1657960400, 701932439,
        2564639411, 4024072741, 453955444, 701932439, 3904355900, 2013832109,
        3904355900, 2517025409, 4225443434, 453955444, 4024072741, 453955444,
        701932439, 3554254580, 3372436105, 3187964447, 878818291, 3707901638,
        3187964447, 4239843955]

XOR_KEY = 0x7F

# Build CRC32 lookup for all bytes
lookup = {}
for c in range(256):
    crc = binascii.crc32(bytes([c])) & 0xFFFFFFFF
    lookup[crc] = c

result = []
for i in range(1, 33):
    target_crc = FLAG[i] ^ XOR_KEY
    if target_crc in lookup:
        result.append(chr(lookup[target_crc]))
    else:
        result.append('?')

flag = ''.join(result)
print(f"Flag: {flag}")

# Verification
all_ok = True
for i, ch in enumerate(flag, 1):
    crc = binascii.crc32(bytes([ord(ch)])) & 0xFFFFFFFF
    check = crc ^ XOR_KEY
    ok = check == FLAG[i]
    if not ok:
        all_ok = False
        print(f"  FAIL at pos {i}: '{ch}'")

if all_ok:
    print("Verification: ALL positions match!")
