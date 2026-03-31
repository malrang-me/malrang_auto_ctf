#!/usr/bin/env python3
"""
Alternative solver: use GF(2) linearity of nonce generator.
Key insight: the nonce generator is a GF(2) linear map.
k_{i+1} = M * k_i over GF(2) where M is a 1024x1024 binary matrix.

We know t_i = 2^{k_i} mod n for each signature.
With known p, q, we can compute k_i mod (smooth part of p-1) and mod (smooth part of q-1)
via Pohlig-Hellman.

Combined with the GF(2) structure, we build a system of linear equations over GF(2)
to recover k1 bit by bit.

Then x = (s1 - k1) * r1_inv mod phi.
"""
import numpy as np
from math import gcd
import time

# Load data
p = 9920522511207756918661387854583635865648000299767569834394571324057930918378630105032761520526067982184168540332545854173360898980873370905258769488648543
q = 8973432238488204111962670498942166433860068598707107555661144421520686596935827350858342612592230396087443152590934524832056213094444814046233818101949301
n = p * q
phi = (p-1)*(q-1)

r1 = 88585709196538809656648270029674022879183854397789706274496480149474816708167227670470284867225138908139866838475139123241745454209025369847853759676867686426820139026151466064288611380567170612110538106652298069704079700210812769253265133872748128337751122001145909770944682857551473798228295330044749256505
s1 = 77089186675882683201549949831307853669079950229743789572581323526369735513309150839461819898055130534700253929611442453618168624051786121140410134299098230239542984539326489483305905096739753460696619871566378700776177767019985404550145890311048824997823139385418801549548746472354826566892635097218358868949
r2 = 34468662633956730456147835642487416362187750109161820935642285369268899177242345972039038778259944778773442646851411529941646711777943265072799373281465541136830021881071206229544923841708928131923780031957993401152573341182241677812502408404072055241192114779512526866796145846250885115898214382793420643706
s2 = 85429203890982151251826189284721582792984811964341749122934314933533981725603517484131431648116738509992497364392775678595778711783007042730511242060473392761775863873362172014375484460529524758479978594532673044608677095048367045345113448550645383607008676825857570879880653766591320360555087210729905667240
r3 = 69713987688355246735813205265302324283276185168693935540832609136660922273366177436658477415010378646704311471986850385356222942517343955646675851307849799555761794911763190203374242839439927890567607132057210335595420868904927651282292158531587700050642908313321976954642497108840449019619752712910887468066
s3 = 68512226449924919155715655650798247127893592852344870583972199512077847737644979571437806228309280947841544810329723785718381090297947053103113328281187785754586424154406648742417429731432029362713324450428731581281036227766478944094038521863522898306205524879319122009138966042799840000843671851146870425199
r4 = 56340175135045551485585518944484596022159726582583031697023308189803272685750218331078538879957277644052772663841513537595458355164559395554652519017867169424057102209294268518231038598820363519514694240510541436882204397286011351511192572645021389143711595459133540855177522010953129784887105252359253596275
s4 = 27628110602355179921205598647985134809348392242521780713820706695809026422045599012709426111110975654136365789533951927727732893950317778751497161028863503002180644210356045705149283079203168031230326928535246398046460975975020059007836745958444855900989132208950523161080818908607577056221072197302176471472
t1 = 4282336956098069033266824568785483901801931648653557892977148775215162748464418821414069619183757886227508295604382739393822210053025701877581076144862861255076821781314958766546253968865384619840775891653677792806323977945334217526466232953672922450300270397678383462990998539069712709359977808033802600661
t2 = 71974300789901375689507881137523675972535829865066283317013564962582357995676521390823858951418013506621522064376393207641647047797008070852757009935885486157553669123273649518283328425558099750752332788272161043115713026216830019145949166259312481513933882033297964252738558861559690021924417865620359645848
t3 = 44983643380261686710781778707861474731477726427011131655776027720933423523298200265601275546626915582462648822184781031555178317879669387065965697903034949013621522729586027708887777618522123366303646281101204019956403707736993391985774094506436028018414954062408113048783461562049174386376698804255084214422
t4 = 34033524103565321365051579003983087032624759837628375446493744754654038654126269530637584959533360884363820291794811035862524965246741550215068656764106991720953365181369119168124061359717059286142016732011070577793657863687247094109483599192463627205344318482553216194099832694286057601572255937484906994267

nb = 1024
g = 2

# Strategy: Pohlig-Hellman on smooth factors to get k_i mod small moduli.
# Then use k_i relationships (nonce generator) to extend.

def pohlig_hellman_subgroup(t_val, g_val, prime, pf):
    """Compute k mod pf where g^k ≡ t (mod prime), in the pf-order subgroup."""
    order = (prime - 1) // pf
    gp = pow(g_val, order, prime)
    tp = pow(t_val, order, prime)

    if pf < 10**7:
        # Brute force for small subgroups
        acc = 1
        for j in range(pf):
            if acc == tp:
                return j
            acc = acc * gp % prime
        return None
    else:
        # BSGS
        import math
        m = int(math.isqrt(pf)) + 1
        baby = {}
        acc = 1
        for j in range(m):
            baby[acc] = j
            acc = acc * gp % prime
        gp_inv_m = pow(gp, -m, prime)
        gamma = tp
        for i in range(m):
            if gamma in baby:
                return (i * m + baby[gamma]) % pf
            gamma = gamma * gp_inv_m % prime
        return None

def pohlig_hellman_partial(t_val, g_val, prime, factors):
    """Get k mod (product of smooth factors) via Pohlig-Hellman."""
    k_mod = 0
    modulus = 1
    for (pf_base, pf_exp) in factors:
        pf = pf_base ** pf_exp
        k_sub = pohlig_hellman_subgroup(t_val % prime, g_val, prime, pf)
        if k_sub is not None:
            # CRT combine
            g_val_check = gcd(modulus, pf)
            if g_val_check == 1:
                # Standard CRT
                M1, M2 = modulus, pf
                _, u1, u2 = extended_gcd(M1, M2)
                k_mod = (k_sub * u1 * M1 + k_mod * u2 * M2) % (M1 * M2)
                modulus = M1 * M2
            else:
                # Non-coprime case - check consistency and merge
                if k_mod % g_val_check == k_sub % g_val_check:
                    lcm_val = modulus * pf // g_val_check
                    # Find k_mod that satisfies both
                    # k ≡ k_mod (mod modulus) and k ≡ k_sub (mod pf)
                    diff = (k_sub - k_mod) // g_val_check
                    mod_reduced = pf // g_val_check
                    mod_inv = pow(modulus // g_val_check, -1, mod_reduced)
                    k_mod = k_mod + modulus * ((diff * mod_inv) % mod_reduced)
                    modulus = lcm_val
        else:
            print(f"  Failed for factor {pf_base}^{pf_exp}")
    return k_mod, modulus

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    return gcd_val, y1 - (b // a) * x1, x1

# Factor p-1 and q-1 (smooth parts only, from earlier analysis)
# Need to factor for THIS specific p, q

print("Factoring p-1...")
t_start = time.time()
from sympy import factorint
fp1 = factorint(p - 1, limit=10**8)
print(f"p-1 factors (limit 10^8): {fp1} ({time.time()-t_start:.1f}s)")

print("Factoring q-1...")
t_start = time.time()
fq1 = factorint(q - 1, limit=10**8)
print(f"q-1 factors (limit 10^8): {fq1} ({time.time()-t_start:.1f}s)")

# Get smooth factors (those fully factored)
def get_smooth_factors(factor_dict, limit=10**15):
    """Extract factors where the base is below limit."""
    smooth = []
    for base, exp in factor_dict.items():
        if base < limit:
            smooth.append((base, exp))
    return smooth

smooth_p = get_smooth_factors(fp1)
smooth_q = get_smooth_factors(fq1)
print(f"Smooth factors of p-1: {smooth_p}")
print(f"Smooth factors of q-1: {smooth_q}")

# Pohlig-Hellman for each signature's nonce
t_vals = [t1, t2, t3, t4]
s_vals = [s1, s2, s3, s4]
r_vals = [r1, r2, r3, r4]

print("\n=== Pohlig-Hellman partial DLP ===")
partial_k_all = []
for idx, t_val in enumerate(t_vals):
    print(f"\n--- Signature {idx+1} ---")

    # Mod p
    kp, mp = pohlig_hellman_partial(t_val, g, p, smooth_p)
    print(f"  k{idx+1} mod {mp} ({mp.bit_length()}b) from p = {kp}")

    # Mod q
    kq, mq = pohlig_hellman_partial(t_val, g, q, smooth_q)
    print(f"  k{idx+1} mod {mq} ({mq.bit_length()}b) from q = {kq}")

    # CRT combine
    g_val = gcd(mp, mq)
    if g_val == 1:
        _, u1, u2 = extended_gcd(mp, mq)
        k_combined = (kq * u1 * mp + kp * u2 * mq) % (mp * mq)
        m_combined = mp * mq
    else:
        if kp % g_val == kq % g_val:
            lcm_val = mp * mq // g_val
            diff = (kq - kp) // g_val
            mod_reduced = mq // g_val
            mod_inv = pow(mp // g_val, -1, mod_reduced)
            k_combined = kp + mp * ((diff * mod_inv) % mod_reduced)
            m_combined = lcm_val
        else:
            print(f"  CRT INCONSISTENT for k{idx+1}")
            k_combined, m_combined = kp, mp

    partial_k_all.append((k_combined, m_combined))
    print(f"  k{idx+1} mod {m_combined} ({m_combined.bit_length()}b) = {k_combined}")

# From each partial k and sig equation: x mod smooth
# s_i = k_i + x * r_i mod phi
# x = (s_i - k_i) * r_i^(-1) mod (smooth modulus)
print("\n=== Recovering x mod smooth ===")
for idx in range(4):
    ki, mi = partial_k_all[idx]
    ri = r_vals[idx]
    si = s_vals[idx]
    g_ri_mi = gcd(ri, mi)
    if g_ri_mi == 1:
        ri_inv = pow(ri, -1, mi)
        x_partial = ((si - ki) * ri_inv) % mi
        print(f"x mod {mi} ({mi.bit_length()}b) from sig {idx+1} = {x_partial}")
    else:
        print(f"gcd(r{idx+1}, m{idx+1}) = {g_ri_mi}, skipping")

print("\n=== Nonce relationship check ===")
# Check: does nonce_next(k1) give k2 mod smooth?
def nonce_next_int(nk, nb_val=1024):
    b = nb_val >> 4
    x = nk
    for i in range(nb_val // 3):
        x ^= nk >> (3 * i)
    x &= (1 << b) - 1
    nk_new = (nk << b) | x
    nk_new &= (1 << nb_val) - 1
    return nk_new

k1_partial, m1 = partial_k_all[0]
k2_partial, m2 = partial_k_all[1]

# nonce_next(k1) mod m2 should == k2_partial
# But k1 is only known mod m1, and nonce_next involves bitwise ops.
# Bitwise ops don't decompose nicely under modular arithmetic.
# However, for mod 2: nonce_next(k1) mod 2 = fold(k1) mod 2
# fold(k1) mod 2 = XOR of k1 bits at positions 0,3,6,...,1020 (mod 2)
# This is the parity of those bits.

# Let's verify with a small example that partial_k are consistent
print(f"k1 mod {m1} = {k1_partial}")
print(f"k2 mod {m2} = {k2_partial}")

# For the nonce generator, the key relationship is:
# k2 = (k1 << 64) | fold(k1) mod 2^1024
# Mod 2: k2 mod 2 = fold(k1) mod 2 = parity of k1 bits at pos 0,3,6,...
# Mod 4: k2 mod 4 = fold(k1) mod 4 (bits 0 and 1 of fold)

# This is where GF(2) analysis helps.
# Each bit of fold depends linearly on k1 bits over GF(2).
# We can build a system of GF(2) equations from:
# 1. The partial DLP info (k_i mod small primes = known values)
# 2. The nonce recurrence (k_{i+1} = linear(k_i) over GF(2))
# 3. The signature equations mod 2 (s_i mod 2 = k_i mod 2 + x*r_i mod 2)

# This gives us a large GF(2) system we can solve.
# Let's build it.

print("\nDone. Partial DLP data collected.")
print("Need to combine with GF(2) nonce structure for full recovery.")
