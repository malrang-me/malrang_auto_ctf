#!/usr/bin/env python3
"""
Analyze diatonic scale properties of chords in the sheet music.
Key of A major: A B C# D E F# G#
"""

# A major scale notes
A_MAJOR = {'A', 'B', 'C#', 'D', 'E', 'F#', 'G#'}

# E major scale notes (in case key sig is 4 sharps)
E_MAJOR = {'E', 'F#', 'G#', 'A', 'B', 'C#', 'D#'}

# All chords from the sheet with their constituent notes
chords = {
    'Aadd9':   ['A', 'B', 'C#', 'E'],        # I add9
    'E':       ['E', 'G#', 'B'],               # V
    'F#m11':   ['F#', 'A', 'C#', 'E', 'G#', 'B'],  # vi m11
    'D':       ['D', 'F#', 'A'],               # IV
    'E7sus4':  ['E', 'A', 'B', 'D'],           # V 7sus4
    'E/G#':    ['E', 'G#', 'B'],               # V/3
    'F#m':     ['F#', 'A', 'C#'],              # vi
    'A':       ['A', 'C#', 'E'],               # I
    'F#m7':    ['F#', 'A', 'C#', 'E'],         # vi 7
    'A/E':     ['A', 'C#', 'E'],               # I/5
    'Bm7':     ['B', 'D', 'F#', 'A'],          # ii 7
    'C7':      ['C', 'E', 'G', 'Bb'],          # NOT DIATONIC in A major
    'F#m9':    ['F#', 'A', 'C#', 'E', 'G#'],   # vi 9
    'A7sus4':  ['A', 'D', 'E', 'G'],           # I 7sus4 - G natural NOT in A major
    'E7sus4_again': ['E', 'A', 'B', 'D'],      # already listed
    # Coda section also has:
    # F#m (already listed)
}

print("=== Chord Analysis in A major ===")
print(f"A major scale: {sorted(A_MAJOR)}")
print()

for name, notes in chords.items():
    non_diatonic = [n for n in notes if n not in A_MAJOR]
    status = "DIATONIC ✓" if not non_diatonic else f"NON-DIATONIC ✗ ({', '.join(non_diatonic)} not in A major)"
    print(f"  {name:15s} = {notes} → {status}")

print()
print("=== Chord Analysis in E major ===")
print(f"E major scale: {sorted(E_MAJOR)}")
print()

for name, notes in chords.items():
    non_diatonic = [n for n in notes if n not in E_MAJOR]
    status = "DIATONIC ✓" if not non_diatonic else f"NON-DIATONIC ✗ ({', '.join(non_diatonic)} not in E major)"
    print(f"  {name:15s} = {notes} → {status}")

print()
print("=== Non-diatonic chords in A major ===")
print("C7 uses C, G, Bb — all outside A major")
print("A7sus4 uses G — outside A major (should be G#)")
print()

print("=== Possible corrections ===")
print("C7 → C#m7 (iii7 in A major, notes: C# E G# B)")
print("C7 → C#7 (V/vi, secondary dominant, notes: C# E# G# B)")
print("A7sus4 → Amaj7sus4? (not standard)")
print("A7sus4 → Could stay as dominant 7 usage (mixolydian)")
print()

print("=== Chord sequence (by measure) ===")
chord_seq = [
    (2, "Aadd9"), (3, "F#m11"),
    (4, "Aadd9"), (4, "E"), (5, "F#m11"),
    (6, "D"), (6, "E"),
    (7, "F#m11"), (8, "A"), (9, "E"), (9, "D"), (9, "E7sus4"),
    (10, "Aadd9"), (11, "E/G#"), (11, "F#m"),
    (12, "E/G#"), (12, "Aadd9"), (12, "E"),
    (13, "F#m"), (14, "D"), (14, "E"),
    (15, "F#m11"), (15, "D"),
    (16, "Aadd9"), (16, "E"), (17, "F#m"), (17, "E"),
    (18, "D"), (18, "E"),
    # Section B
    (19, "A"), (19, "E7sus4"), (19, "A"),
    (20, "D"), (20, "E"),
    (21, "F#m7"), (21, "A/E"),
    (22, "D"), (22, "E"),
    (23, "A"), (23, "E/G#"), (23, "F#m7"), (23, "/E"),
    (24, "D"), (24, "E"),
    (25, "F#m11"), (25, "A7sus4"), (25, "A/E"),
    (26, "D"), (26, "E"),
    (27, "A"), (27, "E7sus4"), (27, "A"),
    (28, "D"), (28, "E"),
    (29, "F#m7"), (29, "A/E"),
    (30, "D"), (30, "E"),
    (31, "A"), (31, "E/G#"), (31, "F#m7"), (31, "/E"),
    (32, "D"), (32, "E"),
    (33, "F#m11"),
    # Coda
    (34, "F#m"), (35, "Bm7"), (35, "C7"),
    (36, "F#m11"),
    (37, "Bm7"), (37, "C7"),
    (38, "F#m9"),
]

# Count unique chords
unique = set(c for _, c in chord_seq if c != "/E")
print(f"Total chord entries: {len(chord_seq)}")
print(f"Unique chords: {len(unique)}")
print(f"Chord set: {sorted(unique)}")

# Count measures
measures = set(m for m, _ in chord_seq)
print(f"Measures with chords: {sorted(measures)}")
print(f"Total measures: {max(measures)}")
