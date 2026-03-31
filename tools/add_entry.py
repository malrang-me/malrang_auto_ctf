#!/usr/bin/env python3
"""Add retroactive SPEEDRUN_MEMORY entries for solved challenges missing entries."""
from pathlib import Path
import re
from datetime import date

PROJECT = Path("/mnt/c/Users/malrangme/Desktop/malrang_auto_ctf")
MEMORY = PROJECT / "knowledge" / "CTF_SPEEDRUN_MEMORY.md"

content = MEMORY.read_text()

# Find last entry number
nums = re.findall(r"## Entry (\d+)", content)
last = max(int(n) for n in nums) if nums else 0

# Check if Basic_CrackME already exists
if "Challenge: Basic_CrackME" in content:
    print("Basic_CrackME already in SPEEDRUN_MEMORY")
else:
    entry_num = f"{last + 1:03d}"
    entry = f"""
---

## Entry {entry_num} - Basic_CrackME
- Challenge: Basic_CrackME
- Category: reversing
- Date: {date.today()}
- Fast Detection Signals:
  - AutoIt compiled script (.exe) with embedded x86 shellcode
  - 32-character input validated character-by-character
  - CRC32 computation inside shellcode (polynomial 0xEDB88320)
  - Hardcoded FLAG array XORed with a key
- Winning Chain:
  - Decompile AutoIt -> extract shellcode -> identify standard CRC32
  - Brute-force XOR key 0~255: count positions that map to printable ASCII
  - Key 0x7F (127) gives 32/32 matches -> DH{{Profitez_des_analyses_AUTOIT}}
  - Why it won: 256-iteration brute is instant, avoids trusting stated key value
- Failure Signatures -> Immediate Fix:
  - Used stated key 0xDEADC0DE directly -> no printable result
  - Fix: AutoIt truncates large integers to byte -> stated key != effective key -> always brute 0~255
- Reusable Assets:
  - CRC32 reverse lookup: brute all printable ASCII, build crc->char map
  - XOR key brute-force with printability scoring (count valid ASCII / total)
  - challenges/Basic_CrackME/solve.py
- Expected Speed-up Next Time:
  - AutoIt + CRC32 + XOR pattern recognized in <5 min -> flag in ~10 min
"""
    with open(MEMORY, "a") as f:
        f.write(entry)
    print(f"✅ Written Entry {entry_num} - Basic_CrackME")
    last += 1

print(f"Total entries: {last}")
