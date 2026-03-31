# Reversal Map: Patch.exe

## Binary Info

| Field | Value |
|---|---|
| File | Patch.exe |
| Format | PE32+ (x86-64), Windows GUI application |
| ImageBase | 0x140000000 |
| Entry Point | (WinMain at 0x1400033b0) |
| .text section | VA 0x140001000, raw offset 0x400, size 0x359c |
| .rdata section | VA 0x140005000, raw offset 0x3a00, size 0x1750 |
| .rsrc section | Contains embedded PNG image |
| Compiler | MSVC (Windows SDK) |
| Dependencies | gdiplus.dll, user32.dll, kernel32.dll |

## GDI+ IAT Layout

All drawing calls target these IAT entries:

| Address | Function |
|---|---|
| 0x140005238 | GdipAlloc |
| 0x140005240 | GdipSetSmoothingMode |
| 0x140005248 | GdipFree |
| 0x140005250 | GdiplusStartup |
| 0x140005258 | GdipDeleteGraphics |
| 0x140005260 | GdipDeletePen |
| 0x140005268 | GdipCreatePen1 |
| 0x140005270 | GdipDrawLineI |
| 0x140005278 | GdipCreateFromHDC |

## Pen Width Constants

| Address | Float Bytes | Value | Usage |
|---|---|---|---|
| 0x1400053e4 | 0x40800000 | 4.0 | Standard character drawing pen |
| 0x1400053e8 | 0x41200000 | 10.0 | Thick obfuscating line pen |

## WndProc Dispatch (0x1400032f0)

- WM_DESTROY (0x02): calls PostQuitMessage
- WM_PAINT (0x0f): initializes GDI+, calls GdipCreateFromHDC, then calls drawing dispatcher 0x140002c40
- WM_LBUTTONUP (0x202): invalidates window rect (triggers repaint)

## Drawing Dispatcher (0x140002c40)

The main drawing function that calls all character drawing functions in order:

```
0x140002c40:
  1. Calls helper 0x140002b80 x25 times (obfuscating lines)
  2. Calls 0x1400017a0 (edx=0x28=40)    -> char "D" at x=40
  3. Calls 0x140001c80 (edx=0x50=80)    -> char "H" at x=80
  4. Calls 0x140002640                  -> char "{" at x=115-135
  5. Calls 0x1400020f0                  -> char "U" at x=160
  6. Calls 0x140002390                  -> char "P" at x=200
  7. Calls 0x140001240                  -> char "A" at x=240
  8. Calls 0x140001f20                  -> char "T" at x=281
  9. Calls 0x140001560                  -> char "C" at x=320
  10. Calls 0x140001c80 (edx=0x168=360) -> char "H" at x=360
  11. Calls 0x1400019d0                 -> char "E" at x=400
  12. Calls 0x1400017a0 (edx=0x1b8=440) -> char "D" at x=440
  13. Calls 0x140002870                 -> char "}" at x=480-500
```

## All Drawing Functions

### Function 0x140001560 - Character "C" at x=320-350
Color: 0xff000000 (opaque black) | Pen width: 4.0 | Segments: 4 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 321 | 30 | 350 | 30 | horizontal top |
| 2 | 320 | 31 | 320 | 60 | vertical left top |
| 3 | 320 | 61 | 320 | 89 | vertical left bottom |
| 4 | 321 | 90 | 350 | 90 | horizontal bottom |

### Function 0x1400017a0 - Character "D" (called twice)
Color: 0xff000000 | Pen width: 4.0 | Segments: 4 per call | Visible: YES

Calling convention: `call 0x1400017a0` with `edx = x_offset`. r14d = edx, r15d = edx + 28.

**Instance 1: edx=0x28=40 (character "D" at x=40)**

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 40 | 31 | 40 | 59 | vertical left top |
| 2 | 40 | 31 | 68 | 59 | diagonal top-right |
| 3 | 68 | 60 | 40 | 88 | diagonal bottom-left |
| 4 | 40 | 60 | 40 | 90 | vertical left bottom |

**Instance 2: edx=0x1b8=440 (character "D" at x=440)**

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 440 | 31 | 440 | 59 | vertical left top |
| 2 | 440 | 31 | 468 | 59 | diagonal top-right |
| 3 | 468 | 60 | 440 | 88 | diagonal bottom-left |
| 4 | 440 | 60 | 440 | 90 | vertical left bottom |

### Function 0x1400019d0 - Character "E" at x=400-430
Color: 0xff000000 | Pen width: 4.0 | Segments: 5 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 401 | 30 | 430 | 30 | horizontal top |
| 2 | 400 | 31 | 400 | 60 | vertical left top |
| 3 | 400 | 61 | 400 | 89 | vertical left bottom |
| 4 | 401 | 90 | 430 | 90 | horizontal bottom |
| 5 | 401 | 60 | 430 | 60 | horizontal middle |

### Function 0x140001c80 - Character "H" (called twice)
Color: 0xff000000 | Pen width: 4.0 | Segments: 5 per call | Visible: YES

Calling convention: `call 0x140001c80` with `edx = x_offset`. r15d = edx, r14d = edx + 30.

**Instance 1: edx=0x50=80 (character "H" at x=80)**

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 80 | 31 | 80 | 59 | vertical left top |
| 2 | 110 | 30 | 110 | 59 | vertical right top |
| 3 | 110 | 61 | 110 | 90 | vertical right bottom |
| 4 | 80 | 60 | 110 | 60 | horizontal middle |
| 5 | 80 | 60 | 80 | 90 | vertical left bottom |

**Instance 2: edx=0x168=360 (character "H" at x=360)**

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 360 | 31 | 360 | 59 | vertical left top |
| 2 | 390 | 30 | 390 | 59 | vertical right top |
| 3 | 390 | 61 | 390 | 90 | vertical right bottom |
| 4 | 360 | 60 | 390 | 60 | horizontal middle |
| 5 | 360 | 60 | 360 | 90 | vertical left bottom |

### Function 0x140001f20 - Character "T" at x=281-310
Color: 0xff000000 | Pen width: 4.0 | Segments: 3 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 281 | 30 | 310 | 30 | horizontal top |
| 2 | 295 | 31 | 295 | 60 | vertical stem top |
| 3 | 295 | 61 | 295 | 89 | vertical stem bottom |

### Function 0x1400020f0 - Character "U" at x=160-190
Color: 0xff000000 | Pen width: 4.0 | Segments: 5 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 160 | 31 | 160 | 60 | vertical left top |
| 2 | 160 | 61 | 160 | 89 | vertical left bottom |
| 3 | 161 | 90 | 190 | 90 | horizontal bottom |
| 4 | 190 | 31 | 190 | 60 | vertical right top |
| 5 | 190 | 61 | 190 | 90 | vertical right bottom |

### Function 0x140001240 - Character "A" at x=240-270
Color: 0xff000000 | Pen width: 4.0 | Segments: 6 | Visible: YES

Note: This function draws what visually appears as "A" (box-style with top cap and middle crossbar).

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 240 | 31 | 240 | 59 | vertical left top |
| 2 | 240 | 29 | 270 | 29 | horizontal top |
| 3 | 270 | 30 | 270 | 59 | vertical right top |
| 4 | 240 | 61 | 240 | 90 | vertical left bottom |
| 5 | 270 | 61 | 270 | 90 | vertical right bottom |
| 6 | 240 | 60 | 270 | 60 | horizontal middle |

### Function 0x140002390 - Character "P" at x=200-230
Color: 0xff000000 | Pen width: 4.0 | Segments: 5 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 200 | 31 | 200 | 59 | vertical left top |
| 2 | 200 | 29 | 230 | 29 | horizontal top |
| 3 | 230 | 30 | 230 | 59 | vertical right top |
| 4 | 200 | 60 | 230 | 60 | horizontal middle |
| 5 | 200 | 60 | 200 | 90 | vertical left bottom |

### Function 0x140002640 - Character "{" at x=115-135
Color: 0xff000000 | Pen width: 4.0 | Segments: 4 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 135 | 30 | 125 | 35 | diagonal top |
| 2 | 125 | 35 | 125 | 85 | vertical main |
| 3 | 125 | 60 | 115 | 60 | horizontal middle nub |
| 4 | 135 | 90 | 125 | 85 | diagonal bottom |

### Function 0x140002870 - Character "}" at x=480-500
Color: 0xff000000 | Pen width: 4.0 | Segments: 4 | Visible: YES

| Segment | x1 | y1 | x2 | y2 | Shape role |
|---|---|---|---|---|---|
| 1 | 490 | 35 | 480 | 30 | diagonal top |
| 2 | 490 | 35 | 490 | 85 | vertical main |
| 3 | 490 | 60 | 500 | 60 | horizontal middle nub |
| 4 | 490 | 85 | 480 | 90 | diagonal bottom |

### Function 0x140002b80 - Single line helper (called 25 times)
Called exclusively from 0x140002c40. Draws one obfuscating line per call.

Signature: `helper(rcx=context, r8d=y1, r9d=x2, [rsp+0x20]=y2, [rsp+0x28]=color)`

- x1 is HARDCODED to 0x96 = 150
- Pen width: 10.0 (thick, value from 0x1400053e8)
- Color: always 0xff000000 (opaque black)

All 25 segments draw FROM x=150 TO various endpoints, creating a fan/cross-hatch pattern that COVERS characters U, P, A, T, C, H, E, D inside the braces:

| Call | x1 | y1 | x2 | y2 |
|---|---|---|---|---|
| 1 | 150 | 30 | 470 | 80 |
| 2 | 150 | 35 | 470 | 75 |
| 3 | 150 | 40 | 470 | 70 |
| 4 | 150 | 45 | 470 | 65 |
| 5 | 150 | 50 | 470 | 60 |
| 6 | 150 | 55 | 470 | 55 |
| 7 | 150 | 60 | 470 | 50 |
| 8 | 150 | 65 | 470 | 45 |
| 9 | 150 | 70 | 470 | 40 |
| 10 | 150 | 75 | 470 | 75 |
| 11 | 150 | 80 | 400 | 60 |
| 12 | 150 | 30 | 470 | 90 |
| 13 | 150 | 35 | 470 | 30 |
| 14 | 150 | 40 | 470 | 35 |
| 15 | 150 | 45 | 470 | 50 |
| 16 | 150 | 50 | 470 | 40 |
| 17 | 150 | 55 | 400 | 90 |
| 18 | 150 | 60 | 470 | 60 |
| 19 | 150 | 65 | 470 | 30 |
| 20 | 150 | 70 | 470 | 80 |
| 21 | 150 | 75 | 470 | 70 |
| 22 | 150 | 80 | 470 | 60 |
| 23 | 150 | 80 | 470 | 80 |
| 24 | 150 | 80 | 470 | 70 |
| 25 | 150 | 90 | 470 | 90 |

## Visible vs Hidden Classification

| Function | Character | x range | Visible | Reason |
|---|---|---|---|---|
| 0x1400017a0 (x=40) | D | 40-68 | YES | Not covered by obfuscating lines |
| 0x140001c80 (x=80) | H | 80-110 | YES | Not covered by obfuscating lines |
| 0x140002640 | { | 115-135 | YES | Not covered by obfuscating lines |
| 0x1400020f0 | U | 160-190 | HIDDEN | Covered by 25 crossing lines (x=150 anchor) |
| 0x140002390 | P | 200-230 | HIDDEN | Covered by 25 crossing lines |
| 0x140001240 | A | 240-270 | HIDDEN | Covered by 25 crossing lines |
| 0x140001f20 | T | 281-310 | HIDDEN | Covered by 25 crossing lines |
| 0x140001560 | C | 320-350 | HIDDEN | Covered by 25 crossing lines |
| 0x140001c80 (x=360) | H | 360-390 | HIDDEN | Covered by 25 crossing lines |
| 0x1400019d0 | E | 400-430 | HIDDEN | Covered by 25 crossing lines |
| 0x1400017a0 (x=440) | D | 440-468 | HIDDEN | Covered by 25 crossing lines (x2 up to 468) |
| 0x140002870 | } | 480-500 | YES | Not covered by obfuscating lines |
| 0x140002b80 (x25) | obfuscation | 150-500 | -- | These ARE the covering lines |

## Complete Line Segment List

Format: (x1, y1) -> (x2, y2) [color: ARGB] [pen_width] [visible/hidden]

### DH{ prefix (visible)

```
# D at x=40 (func 0x1400017a0, instance 1)
(40, 31) -> (40, 59)   [0xff000000] [4.0] [visible]
(40, 31) -> (68, 59)   [0xff000000] [4.0] [visible]
(68, 60) -> (40, 88)   [0xff000000] [4.0] [visible]
(40, 60) -> (40, 90)   [0xff000000] [4.0] [visible]

# H at x=80 (func 0x140001c80, instance 1)
(80, 31) -> (80, 59)   [0xff000000] [4.0] [visible]
(110, 30) -> (110, 59) [0xff000000] [4.0] [visible]
(110, 61) -> (110, 90) [0xff000000] [4.0] [visible]
(80, 60) -> (110, 60)  [0xff000000] [4.0] [visible]
(80, 60) -> (80, 90)   [0xff000000] [4.0] [visible]

# { at x=115 (func 0x140002640)
(135, 30) -> (125, 35) [0xff000000] [4.0] [visible]
(125, 35) -> (125, 85) [0xff000000] [4.0] [visible]
(125, 60) -> (115, 60) [0xff000000] [4.0] [visible]
(135, 90) -> (125, 85) [0xff000000] [4.0] [visible]
```

### UPATCHED (hidden by obfuscating lines)

```
# U at x=160 (func 0x1400020f0)
(160, 31) -> (160, 60)  [0xff000000] [4.0] [hidden]
(160, 61) -> (160, 89)  [0xff000000] [4.0] [hidden]
(161, 90) -> (190, 90)  [0xff000000] [4.0] [hidden]
(190, 31) -> (190, 60)  [0xff000000] [4.0] [hidden]
(190, 61) -> (190, 90)  [0xff000000] [4.0] [hidden]

# P at x=200 (func 0x140002390)
(200, 31) -> (200, 59)  [0xff000000] [4.0] [hidden]
(200, 29) -> (230, 29)  [0xff000000] [4.0] [hidden]
(230, 30) -> (230, 59)  [0xff000000] [4.0] [hidden]
(200, 60) -> (230, 60)  [0xff000000] [4.0] [hidden]
(200, 60) -> (200, 90)  [0xff000000] [4.0] [hidden]

# A at x=240 (func 0x140001240)
(240, 31) -> (240, 59)  [0xff000000] [4.0] [hidden]
(240, 29) -> (270, 29)  [0xff000000] [4.0] [hidden]
(270, 30) -> (270, 59)  [0xff000000] [4.0] [hidden]
(240, 61) -> (240, 90)  [0xff000000] [4.0] [hidden]
(270, 61) -> (270, 90)  [0xff000000] [4.0] [hidden]
(240, 60) -> (270, 60)  [0xff000000] [4.0] [hidden]

# T at x=281 (func 0x140001f20)
(281, 30) -> (310, 30)  [0xff000000] [4.0] [hidden]
(295, 31) -> (295, 60)  [0xff000000] [4.0] [hidden]
(295, 61) -> (295, 89)  [0xff000000] [4.0] [hidden]

# C at x=320 (func 0x140001560)
(321, 30) -> (350, 30)  [0xff000000] [4.0] [hidden]
(320, 31) -> (320, 60)  [0xff000000] [4.0] [hidden]
(320, 61) -> (320, 89)  [0xff000000] [4.0] [hidden]
(321, 90) -> (350, 90)  [0xff000000] [4.0] [hidden]

# H at x=360 (func 0x140001c80, instance 2)
(360, 31) -> (360, 59)  [0xff000000] [4.0] [hidden]
(390, 30) -> (390, 59)  [0xff000000] [4.0] [hidden]
(390, 61) -> (390, 90)  [0xff000000] [4.0] [hidden]
(360, 60) -> (390, 60)  [0xff000000] [4.0] [hidden]
(360, 60) -> (360, 90)  [0xff000000] [4.0] [hidden]

# E at x=400 (func 0x1400019d0)
(401, 30) -> (430, 30)  [0xff000000] [4.0] [hidden]
(400, 31) -> (400, 60)  [0xff000000] [4.0] [hidden]
(400, 61) -> (400, 89)  [0xff000000] [4.0] [hidden]
(401, 90) -> (430, 90)  [0xff000000] [4.0] [hidden]
(401, 60) -> (430, 60)  [0xff000000] [4.0] [hidden]

# D at x=440 (func 0x1400017a0, instance 2)
(440, 31) -> (440, 59)  [0xff000000] [4.0] [hidden]
(440, 31) -> (468, 59)  [0xff000000] [4.0] [hidden]
(468, 60) -> (440, 88)  [0xff000000] [4.0] [hidden]
(440, 60) -> (440, 90)  [0xff000000] [4.0] [hidden]
```

### } suffix (visible)

```
# } at x=480 (func 0x140002870)
(490, 35) -> (480, 30)  [0xff000000] [4.0] [visible]
(490, 35) -> (490, 85)  [0xff000000] [4.0] [visible]
(490, 60) -> (500, 60)  [0xff000000] [4.0] [visible]
(490, 85) -> (480, 90)  [0xff000000] [4.0] [visible]
```

### Obfuscating lines (drawn first, covering UPATCHED)

```
# 25 thick lines anchored at x=150, pen_width=10.0 (func 0x140002b80 via 0x140002c40)
(150, 30) -> (470, 80)  [0xff000000] [10.0] [obfuscating]
(150, 35) -> (470, 75)  [0xff000000] [10.0] [obfuscating]
(150, 40) -> (470, 70)  [0xff000000] [10.0] [obfuscating]
(150, 45) -> (470, 65)  [0xff000000] [10.0] [obfuscating]
(150, 50) -> (470, 60)  [0xff000000] [10.0] [obfuscating]
(150, 55) -> (470, 55)  [0xff000000] [10.0] [obfuscating]
(150, 60) -> (470, 50)  [0xff000000] [10.0] [obfuscating]
(150, 65) -> (470, 45)  [0xff000000] [10.0] [obfuscating]
(150, 70) -> (470, 40)  [0xff000000] [10.0] [obfuscating]
(150, 75) -> (470, 75)  [0xff000000] [10.0] [obfuscating]
(150, 80) -> (400, 60)  [0xff000000] [10.0] [obfuscating]
(150, 30) -> (470, 90)  [0xff000000] [10.0] [obfuscating]
(150, 35) -> (470, 30)  [0xff000000] [10.0] [obfuscating]
(150, 40) -> (470, 35)  [0xff000000] [10.0] [obfuscating]
(150, 45) -> (470, 50)  [0xff000000] [10.0] [obfuscating]
(150, 50) -> (470, 40)  [0xff000000] [10.0] [obfuscating]
(150, 55) -> (400, 90)  [0xff000000] [10.0] [obfuscating]
(150, 60) -> (470, 60)  [0xff000000] [10.0] [obfuscating]
(150, 65) -> (470, 30)  [0xff000000] [10.0] [obfuscating]
(150, 70) -> (470, 80)  [0xff000000] [10.0] [obfuscating]
(150, 75) -> (470, 70)  [0xff000000] [10.0] [obfuscating]
(150, 80) -> (470, 60)  [0xff000000] [10.0] [obfuscating]
(150, 80) -> (470, 80)  [0xff000000] [10.0] [obfuscating]
(150, 80) -> (470, 70)  [0xff000000] [10.0] [obfuscating]
(150, 90) -> (470, 90)  [0xff000000] [10.0] [obfuscating]
```

## Recovered Flag

```
DH{UPATCHED}
```

The flag is drawn in stylized block-letter line segments across x=40 to x=500, y=29 to y=90. The characters "UPATCHED" are drawn over by 25 thick (width=10) crossing lines that originate at x=150 and fan out across the full character region.

## Attack Strategy

**The Hiding Mechanism:**
- All drawing calls use color 0xff000000 (opaque black) - there are NO white-on-white hidden characters.
- The obfuscation uses 25 thick crossing lines (pen width 10.0) drawn by function 0x140002b80.
- These lines anchor at x=150 (left edge of "U") and span to x=400-470 (covering U through D).
- The crossing pattern creates a dense black mesh that makes individual characters illegible.
- The "D" at x=40, "H" at x=80, "{" at x=115, and "}" at x=480 are NOT covered - they are visible.

**How to Patch:**
The challenge title "Patch" and the flag content "UPATCHED" is a word play. To make the flag visible:
1. NOP/remove the 25 calls to helper function 0x140002b80 in 0x140002c40 (addresses 0x140002c6c through 0x140002fcc).
2. OR: Patch GdipDrawLineI calls inside 0x140002b80 to skip drawing.
3. OR: Patch 0x140002c40 to not call 0x140002b80 at all (NOP the region 0x140002c43 to 0x140002fd1).
4. OR: Change the pen width inside 0x140002b80 from 10.0 (0x41200000) to 0.0 at address 0x1400053e8.

The key patch location is at the call instruction `call 0x140002b80` at 0x140002c6c (first of 25 calls). NOPing all 25 call sites reveals the hidden text.

**Drawing Order Note:**
GDI+ draws in call order. The 25 obfuscating lines are drawn FIRST (lines 1-25 in 0x140002c40), then the actual characters are drawn ON TOP. This means on the actual screen, the character lines ARE drawn over the obfuscating lines, but due to the thick pen width and density of the crossing pattern, the characters remain visually obscured.

Wait - on re-examination: the obfuscating lines are drawn first, then the characters. On screen, the characters would appear ON TOP of the obfuscating mesh. The actual display therefore should show the characters visible. The "patch" challenge may require a different approach - perhaps the characters are drawn BEFORE the obfuscating lines in a different order, or the drawing order in 0x140002c40 should be examined more carefully.

**Re-verified Drawing Order in 0x140002c40:**
```
0x140002c40 entry:
  [0x140002c6c - 0x140002fcc]: 25 calls to 0x140002b80 (obfuscating lines) <- DRAWN FIRST
  [0x140002fd1 - 0x140003090]: calls to character drawing functions     <- DRAWN SECOND
```

Since GDI+ renders in order and later calls overdraw earlier calls, the characters are painted OVER the obfuscating mesh. The visual result depends on window background color and overall thickness. The challenge is that visually with thick (w=10) black lines as a base layer, and then thin (w=4) black character lines on top on a white background, the characters are STILL obscured visually because:
1. The thick lines (10px wide) fill large areas
2. The character lines (4px wide) are subsumed in the noise

The patch solution is to remove the 25 obfuscating line calls from the binary.

## Patch Location

| Address | Instruction | Action |
|---|---|---|
| 0x140002c6c | call 0x140002b80 | NOP (first obfuscating call) |
| 0x140002c90 | call 0x140002b80 | NOP |
| ... | ... | NOP all 25 calls |
| 0x140002fcc | call 0x140002b80 | NOP (last obfuscating call) |

Each `call` instruction is 5 bytes (E8 xx xx xx xx). Replace with `90 90 90 90 90` (5 x NOP).

Alternatively, modify the region 0x140002c43-0x140002fd0 to immediately jump to 0x140002fd1.
