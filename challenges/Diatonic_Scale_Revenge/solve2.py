#!/usr/bin/env python3
"""
Broader brute force: try different tempo values and key combinations
"""
import random
from hashlib import sha256
from Crypto.Cipher import AES
import string
import sys

CT = bytes.fromhex(
    "f0509319eab2fd63d05ad829b9e8ade4"
    "2624ac30a2841ee1f130db7ad050a6b5"
    "943d959ba5fce6e169950505f310f105"
    "ba0b44ada8d8da605f20e97256e2db24"
)

def try_decrypt(key_of_song, tempo, secret):
    r = random.Random(key_of_song)
    nums = [r.getrandbits(32) for _ in range(tempo)]
    p = 1
    for i in nums:
        p *= i
    key = sha256((str(secret) + str(p)).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(CT)
    pad_byte = pt[-1]
    if pad_byte == 0 or pad_byte > 16:
        return None
    if pt[-pad_byte:] != bytes([pad_byte]) * pad_byte:
        return None
    pt = pt[:-pad_byte]
    try:
        text = pt.decode('utf-8', errors='strict')
    except:
        return None
    return text

def search_tempo_range(key_of_song, tempo_range, secret_range):
    """Try all combos of tempo and secret"""
    for tempo in tempo_range:
        # Precompute p for this tempo
        r = random.Random(key_of_song)
        nums = [r.getrandbits(32) for _ in range(tempo)]
        p = 1
        for i in nums:
            p *= i
        p_str = str(p)

        for secret in secret_range:
            key = sha256((str(secret) + p_str).encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(CT)
            pad_byte = pt[-1]
            if pad_byte == 0 or pad_byte > 16:
                continue
            if pt[-pad_byte:] != bytes([pad_byte]) * pad_byte:
                continue
            pt = pt[:-pad_byte]
            try:
                text = pt.decode('utf-8', errors='strict')
            except:
                continue
            if any(text.startswith(prefix) for prefix in ['DH{', 'flag{', 'hspace{', 'FLAG{', 'HSPACE{']):
                print(f"\n[!!!] FOUND! key='{key_of_song}', tempo={tempo}, secret={secret}")
                print(f"[!!!] Decrypted: {text}")
                return text
            if '{' in text and '}' in text and all(c in string.printable for c in text):
                print(f"[?] key='{key_of_song}', tempo={tempo}, secret={secret}: {repr(text)}")

    return None

def search_string_secrets(key_of_song, tempo, secrets_list):
    """Try string secrets"""
    r = random.Random(key_of_song)
    nums = [r.getrandbits(32) for _ in range(tempo)]
    p = 1
    for i in nums:
        p *= i
    p_str = str(p)

    for secret in secrets_list:
        key = sha256((str(secret) + p_str).encode()).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(CT)
        pad_byte = pt[-1]
        if pad_byte == 0 or pad_byte > 16:
            continue
        if pt[-pad_byte:] != bytes([pad_byte]) * pad_byte:
            continue
        pt = pt[:-pad_byte]
        try:
            text = pt.decode('utf-8', errors='strict')
        except:
            continue
        if '{' in text and '}' in text:
            print(f"[!!!] key='{key_of_song}', tempo={tempo}, secret='{secret}': {text}")
            return text
    return None

# String candidates for secret — song names, music terms, etc.
string_secrets = [
    # Chord names
    "C7", "A7sus4", "C#m7", "C#7", "Aadd9", "F#m11", "E7sus4", "E/G#",
    "F#m", "F#m7", "A/E", "Bm7", "F#m9", "D", "E", "A",
    # Possible song names (Korean pop songs in A major, BPM ~70)
    "봄날", "Spring Day", "밤편지", "Through the Night", "에잇",
    "Eight", "사랑하기 때문에", "Love", "Star", "별",
    "좋은 날", "Good Day", "Palette", "팔레트",
    "라일락", "Lilac", "Blueming", "블루밍",
    "피아노", "Piano", "scale", "diatonic",
    "Diatonic", "Diatonic Scale", "revenge", "Revenge",
    # Music terms
    "major", "minor", "sharp", "flat", "chord", "note",
    "tempo", "key", "scale", "diatonic", "chromatic",
    # Other
    "거북목마스터", "turtle", "flag", "secret", "password",
    "hspace", "dreamhack", "ctf",
    # Numbers as strings
    "70", "39", "4", "3",
    # Common Korean song titles
    "좋니", "눈의 꽃", "거짓말", "꽃", "나의 옛날이야기",
    "여행", "에잇", "이 밤", "Love poem", "Celebrity",
    "Coin", "BBIBBI", "나만 없어 고양이", "아이와 나의 바다",
]

if __name__ == "__main__":
    # Phase 1: Try key="A", all tempos 1-200, secret 0-10000
    print("=== Phase 1: key='A', tempo 1-200, secret 0-10000 ===")
    result = search_tempo_range("A", range(1, 201), range(10001))
    if result:
        sys.exit(0)

    # Phase 2: Try key="E", all tempos 1-200, secret 0-10000
    print("\n=== Phase 2: key='E', tempo 1-200, secret 0-10000 ===")
    result = search_tempo_range("E", range(1, 201), range(10001))
    if result:
        sys.exit(0)

    # Phase 3: String secrets with key=A/E, tempo=70
    print("\n=== Phase 3: String secrets ===")
    for key in ["A", "E", "a", "e"]:
        for tempo in [70, 39, 33, 4, 38]:
            result = search_string_secrets(key, tempo, string_secrets)
            if result:
                sys.exit(0)

    # Phase 4: Try multi-char keys with tempo=70
    print("\n=== Phase 4: Multi-char keys, tempo=70, secret 0-10000 ===")
    multi_keys = [
        "Am", "Em", "F#", "F#m", "C#m", "C#", "G#m", "G#",
        "A major", "E major", "F# minor", "C# minor",
        "Amaj", "Emaj", "Amin", "Emin",
    ]
    for key in multi_keys:
        result = search_tempo_range(key, [70], range(10001))
        if result:
            sys.exit(0)

    print("\n[-] All attempts failed.")
