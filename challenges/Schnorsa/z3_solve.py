#!/usr/bin/env python3
"""
Schnorsa Z3 solver: use bitvector Z3 to find k1 from nonce overlap + sig equations.
After eliminating x, we get 3 equations in k1 (1024-bit bitvec).
k2,k3,k4 are determined from k1 via nonce generator (bitwise ops).
"""
from z3 import *
import time

# Data from server
p = 9920522511207756918661387854583635865648000299767569834394571324057930918378630105032761520526067982184168540332545854173360898980873370905258769488648543
q = 8973432238488204111962670498942166433860068598707107555661144421520686596935827350858342612592230396087443152590934524832056213094444814046233818101949301
n = p * q
phi = (p-1)*(q-1)
e = 65537
y = 52345356045556578269564948058641458754238917824543455636451582420355209257512781948074802800902166428005096362670284397311489208629157379565989315038715295897957814440558451107359808943347863468870916697179988075406692066090400577984759298069645918981827125524696394227000979265371511302223554568178068869911
nb = 1024
g = 2

r1 = 88585709196538809656648270029674022879183854397789706274496480149474816708167227670470284867225138908139866838475139123241745454209025369847853759676867686426820139026151466064288611380567170612110538106652298069704079700210812769253265133872748128337751122001145909770944682857551473798228295330044749256505
s1 = 77089186675882683201549949831307853669079950229743789572581323526369735513309150839461819898055130534700253929611442453618168624051786121140410134299098230239542984539326489483305905096739753460696619871566378700776177767019985404550145890311048824997823139385418801549548746472354826566892635097218358868949
r2 = 34468662633956730456147835642487416362187750109161820935642285369268899177242345972039038778259944778773442646851411529941646711777943265072799373281465541136830021881071206229544923841708928131923780031957993401152573341182241677812502408404072055241192114779512526866796145846250885115898214382793420643706
s2 = 85429203890982151251826189284721582792984811964341749122934314933533981725603517484131431648116738509992497364392775678595778711783007042730511242060473392761775863873362172014375484460529524758479978594532673044608677095048367045345113448550645383607008676825857570879880653766591320360555087210729905667240
r3 = 69713987688355246735813205265302324283276185168693935540832609136660922273366177436658477415010378646704311471986850385356222942517343955646675851307849799555761794911763190203374242839439927890567607132057210335595420868904927651282292158531587700050642908313321976954642497108840449019619752712910887468066
s3 = 68512226449924919155715655650798247127893592852344870583972199512077847737644979571437806228309280947841544810329723785718381090297947053103113328281187785754586424154406648742417429731432029362713324450428731581281036227766478944094038521863522898306205524879319122009138966042799840000843671851146870425199
r4 = 56340175135045551485585518944484596022159726582583031697023308189803272685750218331078538879957277644052772663841513537595458355164559395554652519017867169424057102209294268518231038598820363519514694240510541436882204397286011351511192572645021389143711595459133540855177522010953129784887105252359253596275
s4 = 27628110602355179921205598647985134809348392242521780713820706695809026422045599012709426111110975654136365789533951927727732893950317778751497161028863503002180644210356045705149283079203168031230326928535246398046460975975020059007836745958444855900989132208950523161080818908607577056221072197302176471472

# Precompute W values: r_j*s_i - r_i*s_j mod phi
W12 = (r2*s1 - r1*s2) % phi
W13 = (r3*s1 - r1*s3) % phi
W14 = (r4*s1 - r1*s4) % phi

print(f"W12 = {W12}")
print(f"W13 = {W13}")

# Nonce generator in Z3 bitvector
def nonce_next_z3(nk, nb_val=1024):
    b = nb_val >> 4  # 64
    x = nk
    for i in range(nb_val // 3):  # 341
        x = x ^ LShR(nk, 3*i)
    x = x & BitVecVal((1 << b) - 1, nb_val)
    nk_new = (nk << b) | x
    return nk_new

# Z3 setup
BW = 1024
k1 = BitVec('k1', BW)

print("Computing k2, k3, k4 from k1...")
t_start = time.time()
k2 = nonce_next_z3(k1, BW)
k3 = nonce_next_z3(k2, BW)
k4 = nonce_next_z3(k3, BW)
print(f"Nonce chain built in {time.time()-t_start:.1f}s")

# The constraint: r_j * k_i - r_i * k_j ≡ W_ij (mod phi)
# Rewrite: (r_j * k_i - r_i * k_j - W_ij) mod phi == 0
#
# In Z3 bitvectors, we need to handle the modular arithmetic carefully.
# Since k_i < 2^1024 and r_i < 2^1024 and phi < 2^1024,
# r_j * k_i can be up to 2^2048. We need wider bitvectors.

# Extend to 2048 bits for multiplication
BW2 = 2048
phi_bv = BitVecVal(phi, BW2)

def extend(v):
    return ZeroExt(BW2 - BW, v)

k1e = extend(k1)
k2e = extend(k2)
k3e = extend(k3)
k4e = extend(k4)

r1_bv = BitVecVal(r1, BW2)
r2_bv = BitVecVal(r2, BW2)
r3_bv = BitVecVal(r3, BW2)
r4_bv = BitVecVal(r4, BW2)
W12_bv = BitVecVal(W12, BW2)
W13_bv = BitVecVal(W13, BW2)
W14_bv = BitVecVal(W14, BW2)

s = Solver()
s.set("timeout", 600000)  # 10 min timeout

# Constraint 1: (r2*k1 - r1*k2) mod phi == W12
print("Adding constraint 1...")
expr1 = r2_bv * k1e - r1_bv * k2e
# Actually bitvec subtraction might underflow. Use modular form:
# (r2*k1 - r1*k2 - W12) mod phi == 0
# Rewrite as: (r2*k1 + phi - r1*k2 + phi - W12) mod phi == 0 if needed
# But Z3 URem handles unsigned. Need to be careful with signs.
# Use: (r2*k1 + phi*r1 - r1*k2) to avoid negative intermediate values?
# Actually in bitvector arithmetic, subtraction wraps around (2's complement).
# URem for unsigned remainder should work since all values are positive and < 2^2048.

# Alternative: just check that (r2*k1 - r1*k2 - W12) is divisible by phi
# i.e., URem(r2*k1 - r1*k2 - W12, phi) == 0
# But subtraction can wrap. Use: (r2*k1 + (phi - r1*k2 mod phi) + phi - W12) etc.
# This is getting messy. Let me use a cleaner approach.

# Clean approach: compute everything mod phi using intermediate variables
# val = (r2*k1) mod phi + phi - (r1*k2) mod phi
# val mod phi should == W12

# Actually simplest: assert (r2*k1 - r1*k2) % phi == W12
# In Z3: URem(r2_bv * k1e - r1_bv * k2e, phi_bv) == W12_bv
# But negative wraps in bitvec. Since r2*k1 could be < r1*k2, the subtraction wraps.
# Use: URem((r2_bv * k1e - r1_bv * k2e) + phi_bv * BitVecVal(2**1024, BW2), phi_bv)
# Adding a large multiple of phi doesn't change the remainder.
# But 2^1024 * phi is huge. Just add enough multiples.

# Actually, for unsigned bitvectors, (a - b) mod 2^BW2 when a < b gives 2^BW2 - (b-a).
# URem of this by phi might not give the right answer.
#
# SAFER: compute a mod phi and b mod phi separately, then subtract mod phi.
# (r2*k1 mod phi - r1*k2 mod phi + phi) mod phi == W12

val1_12 = URem(r2_bv * k1e, phi_bv)
val2_12 = URem(r1_bv * k2e, phi_bv)
s.add(URem(val1_12 - val2_12 + phi_bv, phi_bv) == W12_bv)

print("Adding constraint 2...")
val1_13 = URem(r3_bv * k1e, phi_bv)
val2_13 = URem(r1_bv * k3e, phi_bv)
s.add(URem(val1_13 - val2_13 + phi_bv, phi_bv) == W13_bv)

print("Adding constraint 3...")
val1_14 = URem(r4_bv * k1e, phi_bv)
val2_14 = URem(r1_bv * k4e, phi_bv)
s.add(URem(val1_14 - val2_14 + phi_bv, phi_bv) == W14_bv)

# Also constrain k1 < 2^1024
s.add(ULT(k1, BitVecVal(2**1024, BW)))

print(f"Solving... (timeout 10 min)")
t_start = time.time()
result = s.check()
t_elapsed = time.time() - t_start
print(f"Result: {result} in {t_elapsed:.1f}s")

if result == sat:
    m = s.model()
    k1_val = m[k1].as_long()
    print(f"k1 = {k1_val}")
    print(f"k1 bits = {k1_val.bit_length()}")

    # Recover x
    r1_inv = pow(r1, -1, phi)
    x = ((s1 - k1_val) * r1_inv) % phi
    print(f"x = {x}")

    # Verify: g^x mod n == y?
    if pow(g, x, n) == y:
        print(f"VERIFIED! g^x mod n == y")
    else:
        print(f"Verification FAILED. Trying x + phi variants...")
        for delta in range(-2, 3):
            x_try = x + delta * phi
            if x_try > 0 and pow(g, x_try, n) == y:
                print(f"Found x with delta={delta}: {x_try}")
                x = x_try
                break

    print(f"\n=== FINAL ANSWER ===")
    print(f"x = {x}")
else:
    print("UNSAT or TIMEOUT. Need different approach.")
