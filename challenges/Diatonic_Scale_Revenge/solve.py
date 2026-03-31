#!/usr/bin/env python3
"""
Diatonic Scale Revenge — Music Theory + AES Crypto
1. Identify key_of_song from sheet music key signature
2. tempo = 70 (from sheet)
3. Brute-force 'secret' to decrypt AES-ECB ciphertext
4. Decrypted flag contains "?->?" — replace with wrong_chord->correct_chord
"""
import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import string
import sys

CT = bytes.fromhex(
    "f0509319eab2fd63d05ad829b9e8ade4"
    "2624ac30a2841ee1f130db7ad050a6b5"
    "943d959ba5fce6e169950505f310f105"
    "ba0b44ada8d8da605f20e97256e2db24"
)

TEMPO = 70  # from sheet: quarter note = 70

def compute_p(key_of_song, tempo):
    """Compute product of random numbers seeded by key_of_song"""
    r = random.Random(key_of_song)
    nums = [r.getrandbits(32) for _ in range(tempo)]
    p = 1
    for i in nums:
        p *= i
    return p

def try_decrypt(secret, p):
    """Try to decrypt with given secret and precomputed p"""
    key = sha256((str(secret) + str(p)).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(CT)
    # Check PKCS7 padding
    pad_byte = pt[-1]
    if pad_byte == 0 or pad_byte > 16:
        return None
    if pt[-pad_byte:] != bytes([pad_byte]) * pad_byte:
        return None
    pt = pt[:-pad_byte]
    # Check if it looks like a flag
    try:
        text = pt.decode('utf-8', errors='strict')
    except:
        return None
    return text

def brute_force_integers(key_of_song, max_secret=1000000):
    """Brute-force secret as integer"""
    p = compute_p(key_of_song, TEMPO)
    p_str = str(p)
    print(f"[*] Trying key='{key_of_song}', tempo={TEMPO}")
    print(f"[*] p has {len(p_str)} digits")
    print(f"[*] Brute-forcing secret as integer 0..{max_secret}")

    for secret in range(max_secret + 1):
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
        if any(text.startswith(prefix) for prefix in ['DH{', 'flag{', 'hspace{', 'FLAG{']):
            print(f"\n[!!!] FOUND! secret={secret}")
            print(f"[!!!] Decrypted: {text}")
            return text
        # Also check for printable text with { and }
        if '{' in text and '}' in text and all(c in string.printable for c in text):
            print(f"\n[?] Possible: secret={secret}: {text}")

        if secret % 100000 == 0 and secret > 0:
            print(f"  ... tried {secret}")

    print(f"[-] No match found for key='{key_of_song}'")
    return None

def brute_force_strings(key_of_song, candidates):
    """Try specific string candidates for secret"""
    p = compute_p(key_of_song, TEMPO)
    p_str = str(p)
    print(f"[*] Trying {len(candidates)} string candidates for key='{key_of_song}'")

    for secret in candidates:
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
        if any(text.startswith(prefix) for prefix in ['DH{', 'flag{', 'hspace{', 'FLAG{']):
            print(f"\n[!!!] FOUND! secret='{secret}'")
            print(f"[!!!] Decrypted: {text}")
            return text
        if '{' in text and '}' in text and all(c in string.printable for c in text):
            print(f"[?] Possible: secret='{secret}': {text}")

    return None

if __name__ == "__main__":
    # Chord names from the sheet music
    chord_names = [
        "Aadd9", "E", "F#m11", "D", "E7sus4", "E/G#", "F#m", "A",
        "F#m7", "A/E", "Bm7", "C7", "F#m9", "A7sus4",
        # Possible corrections
        "C#m7", "C#7", "C#m", "C#", "Amaj7sus4", "Amaj7",
        "D#dim", "G#m", "G#dim", "B", "Bm",
        # Chord corrections as strings
        "C7->C#m7", "C7->C#7", "C7->C#m", "A7sus4->Amaj7sus4",
        "A7sus4->Amaj7", "C7->C#dim",
    ]

    # Note names and single letters
    note_names = list("ABCDEFG") + list("abcdefg") + [
        "A#", "Bb", "C#", "Db", "D#", "Eb", "F#", "Gb", "G#", "Ab",
    ]

    # Musical keys to try for key_of_song
    keys_to_try = ["A", "E", "a", "e"]  # A major (3#), E major (4#)

    for key in keys_to_try:
        # Try string candidates first (fast)
        result = brute_force_strings(key, chord_names + note_names)
        if result:
            break

        # Try integers
        result = brute_force_integers(key, max_secret=1000000)
        if result:
            break

    if not result:
        # Try all single letters as key_of_song
        print("\n[*] Trying all single letters as key_of_song...")
        for key in string.ascii_letters:
            if key in ['A', 'E', 'a', 'e']:
                continue  # Already tried
            result = brute_force_integers(key, max_secret=100000)
            if result:
                break

    if result:
        print(f"\n{'='*60}")
        print(f"Decrypted flag (raw): {result}")
        print(f"{'='*60}")
        print(f"\nNow identify the wrong chord in the sheet music and")
        print(f"replace '?->?' with 'WrongChord->CorrectChord'")
    else:
        print("\n[-] Failed to decrypt. Need to reconsider approach.")
