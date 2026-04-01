#!/usr/bin/env python3
"""Solver for RBG+ (KalmarCTF 2026 / Dreamhack 2822)

Attack: y_{i+1} = y_i^3 * K mod N => y_{i+1}^4 = y_i^3 * y_{i+2} mod N
Express y_k = S_k + (-1)^k * y_0, get polynomial equations in y_0 mod N.
Polynomial GCD recovers y_0 (or factors N as a bonus).
Then common modulus attack to recover m.
"""

from math import gcd
from Crypto.Util.number import long_to_bytes

N = 9973283250672936357436682730468317821051134027083546618280572119672871529171635139300280175294431596376009647341704153633552028468618322897721756655113059977280850865191730622809535742361609719279590664810444798178773554449
e0 = 2282001629752954443222925522704416391364726491022937327924851513678230914043136461138513245660747928710088336187213249929405762461865209092856690754986639369246107893012460738860609755591342904586058644902919593854578128216

c = [
    9326768310711614306181558284803471468379159294591902975874605674623740243276134604748592713429059377144950071235742224045524264061444711907991788174097167539294437449521831567155905942280547598210496397809740411674976019723,
    9596978100383256915954209302007053779074022265757442295257296872578330664191665766637143036561822835676418370538278960948555952215679652501749567819869007847411914524104389284436175216889604496824709369398599013868256042098,
    7994208784758084584345335599288133168863258655660244681485606621791282532307726051176357340131101424947320589340922852640862362352236647556627199344912790755431417482562045054558492530469392497530336950611358077410389327631,
    10427733128913314550149196557591631279662617155340401363125056491460175038340152847281671814719402086381941950062316874292847903159920545447198995859189586767523009620028204929795803199768084535289613081983157244936404062356,
    17739902440882306545367189296889683555454817431339784218571929341141554247871761158872191997140712590855077200642150806576848015144220457188347320319091502711224030156976022551508765714839776626598492575382810279573197611531,
    16960692084593167012899201043624023062014917317220318423261442188402409811920774755747806613373137523536859494261842090019399994669253108865120543620018176875986493662992475578680155784699988738308854246668589380766851132249,
    15980998464830241039198956121444260436102114242386223088542016658342616096344343396516032150874226209661610689755815099163083681954430551663073660551639161289728606540541667060693530138603137074934853876866929858686120914035,
    10129247029943533160664306774441814853012067505510032728174129803283691060828142569229292262883863939259100016864416535090922905092866031124171619848864183763981032864141212715967305520374950681898273348612729185831246838782,
    10321740612639774062750253895296507363351165849924958737945326787337433331191848224844337515490418978746016822118851711095219975314535381855778636801803329248091807802330530106685211638400747309582599472997692622638703050185,
    15859795742929753158565294519344217191787416941034750379832505524717885698043013892872958207174259770307518308529227695981050391823829726968651511286065682836875874253681502470811283157366905954155704512579155953580501517385,
    10178946731501385658683400678651829601947612689639834666224524002668591235052962110637165337953157957374294292775904751434955207947386868922324461064648869015553097688857828467704724813365330163626696519978399781359374509155,
    3360014371510790385735229898625254919616125419557648251532807749180128747552002847457815130641620641810953851506857948113953692616747431504872395358413865355160206155389175061260578809751615213365928588668067342710170805841,
    2233683505541855771762932806658153302428855982846521822025154321266393505647340857986656761966559029940148520986193236102060595680843602573645940731448746954126671188487042834667928563512447789050288602564370153343118347607,
]

# Compute all exponents via LCG
e = [e0]
for i in range(13):
    e.append((e[-1] * 3 + 1337) % N)

# y_k = S_k + (-1)^k * y_0 where S_k is alternating partial sum
# S_0 = 0, S_k = c_{k-1} - S_{k-1}
S = [0]
for k in range(1, 14):
    S.append(c[k-1] - S[k-1])

print("=== S values (first few) ===")
for k in range(4):
    print(f"  S[{k}] = {S[k]}")

# --- Polynomial arithmetic over Z/NZ ---
def poly_strip(f):
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    return f

def poly_mul(f, g):
    r = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        if a == 0: continue
        for j, b in enumerate(g):
            r[i+j] = (r[i+j] + a * b) % N
    return poly_strip(r)

def poly_pow(f, n):
    if n == 0: return [1]
    if n == 1: return f[:]
    half = poly_pow(f, n // 2)
    r = poly_mul(half, half)
    if n % 2: r = poly_mul(r, f)
    return r

def poly_sub(f, g):
    r = [0] * max(len(f), len(g))
    for i in range(len(f)): r[i] = f[i]
    for i in range(len(g)): r[i] = (r[i] - g[i]) % N
    return poly_strip(r)

def poly_divmod(f, g):
    """Returns (quotient, remainder). May raise with factor of N."""
    f = [x % N for x in f]
    g = [x % N for x in g]
    poly_strip(f); poly_strip(g)
    if not g or g == [0]:
        raise ValueError("division by zero poly")

    lc = g[-1]
    d = gcd(lc, N)
    if 1 < d < N:
        return None, None, d  # Found factor!
    lc_inv = pow(lc, -1, N)

    q = [0] * max(1, len(f) - len(g) + 1)
    f = f[:]
    while len(f) >= len(g):
        if f[-1] == 0:
            f.pop()
            continue
        coef = (f[-1] * lc_inv) % N
        deg = len(f) - len(g)
        q[deg] = coef
        for i in range(len(g)):
            f[deg + i] = (f[deg + i] - coef * g[i]) % N
        poly_strip(f)
    return poly_strip(q), poly_strip(f), None

def poly_gcd(f, g):
    """GCD over Z/NZ. Returns (gcd_poly, factor_of_N_or_None)."""
    while g and g != [0]:
        _, r, factor = poly_divmod(f, g)
        if factor:
            return None, factor
        f, g = g, r if r else [0]
    return poly_strip(f), None

# --- Build equations ---
# Eq from triplet (y_0, y_1, y_2): y_1^4 = y_0^3 * y_2 mod N
# y_0 = x, y_1 = S[1] - x, y_2 = S[2] + x
# => (S[1] - x)^4 = x^3 * (S[2] + x)  mod N

def make_eq(k):
    """Triplet (y_k, y_{k+1}, y_{k+2}): y_{k+1}^4 = y_k^3 * y_{k+2} mod N
    y_j = S[j] + (-1)^j * x
    """
    def lin(j):
        # S[j] + (-1)^j * x  =>  [S[j] % N, (-1)^j % N]
        sign = 1 if j % 2 == 0 else -1
        return [S[j] % N, sign % N]

    lhs = poly_pow(lin(k+1), 4)
    rhs = poly_mul(poly_pow(lin(k), 3), lin(k+2))
    return poly_sub(lhs, rhs)

print("\n=== Building polynomial equations ===")
f0 = make_eq(0)
f1 = make_eq(1)
print(f"  deg(f0) = {len(f0)-1}, deg(f1) = {len(f1)-1}")

print("\n=== Computing polynomial GCD ===")
result, factor = poly_gcd(f0, f1)

if factor:
    print(f"  Found factor of N: {factor}")
    p = factor
    q = N // p
    assert p * q == N
    print(f"  p = {p}")
    print(f"  q = {q}")

    # Factor N -> compute phi -> decrypt any ciphertext
    phi = (p - 1) * (q - 1)

    # Recover y_0 from polynomial equation mod p
    # Just try all roots of f0 mod p (degree 4, at most 4 roots)
    # Actually p is 371-bit, can't brute force. Use proper root finding.
    # Instead: use the sum constraints + factored N to decrypt directly

    # We need y_0. From the GCD failure, we know a factor.
    # Let's solve f0(x) = 0 mod p and mod q separately.
    from sympy import Poly, GF, Symbol
    # Actually, let's just solve the polynomial mod p
    # f0 is degree 4 mod p - use Sage or brute in smaller field? p is 371-bit...
    # Better: use the factorization directly.
    # d = gcd(e[0], phi)
    # if d == 1: m = pow(y_0_ciphertext, pow(e[0], -1, phi), N)
    # But we need y_0 first...

    # Alternative: pick any e_i, compute d_i = e_i^{-1} mod phi, then m = y_i^{d_i} mod N
    # But we still need at least one y_i value.

    # Use the sum equations: c_0 = y_0 + y_1, and y_1 = y_0^3 * K mod N
    # With factored N, we can try each root of f0 mod p and mod q, CRT to get y_0

    # Solve f0(x) = 0 mod p using Sage polynomial
    # For now, let's use a simpler approach:
    # Solve the equation over GF(p) and GF(q)

    print("\n=== Solving f0(x) = 0 mod p and mod q ===")

    def poly_roots_mod_prime(coeffs, prime):
        """Find roots of polynomial mod prime using brute force on small polys
        or Berlekamp/Cantor-Zassenhaus for larger."""
        # Use the fact that x^p = x mod p
        # Compute gcd(f(x), x^p - x) mod p to get product of (x - root)
        # Then factor
        from functools import reduce

        # Reduce coefficients mod prime
        cs = [c % prime for c in coeffs]

        # For degree 4, we can use x^p mod f(x) and then gcd(x^p - x, f(x))
        # x^p mod f(x) using repeated squaring
        def pm_mul(a, b, mod_poly, p):
            r = [0] * (len(a) + len(b) - 1)
            for i, ai in enumerate(a):
                if ai == 0: continue
                for j, bj in enumerate(b):
                    r[i+j] = (r[i+j] + ai * bj) % p
            # Reduce mod mod_poly
            while len(r) >= len(mod_poly):
                if r[-1] == 0:
                    r.pop()
                    continue
                lc_inv = pow(mod_poly[-1], -1, p)
                coef = (r[-1] * lc_inv) % p
                deg = len(r) - len(mod_poly)
                for i in range(len(mod_poly)):
                    r[deg+i] = (r[deg+i] - coef * mod_poly[i]) % p
                while r and r[-1] == 0: r.pop()
            if not r: r = [0]
            return r

        def pm_pow(base, exp, mod_poly, p):
            result = [1]
            base = base[:]
            while exp > 0:
                if exp & 1:
                    result = pm_mul(result, base, mod_poly, p)
                base = pm_mul(base, base, mod_poly, p)
                exp >>= 1
            return result

        # x^p mod f(x)
        xp = pm_pow([0, 1], prime, cs, prime)
        # x^p - x
        xp_minus_x = xp[:]
        if len(xp_minus_x) < 2:
            xp_minus_x.extend([0] * (2 - len(xp_minus_x)))
        xp_minus_x[1] = (xp_minus_x[1] - 1) % prime
        while xp_minus_x and xp_minus_x[-1] == 0: xp_minus_x.pop()
        if not xp_minus_x: xp_minus_x = [0]

        # gcd(f(x), x^p - x) mod prime
        def pgcd(a, b, p):
            a = [x % p for x in a]
            b = [x % p for x in b]
            while a and a[-1] == 0: a.pop()
            while b and b[-1] == 0: b.pop()
            if not a: a = [0]
            if not b: b = [0]
            while b != [0] and b:
                # a mod b
                a2 = a[:]
                lc_inv = pow(b[-1], -1, p)
                while len(a2) >= len(b):
                    if a2[-1] == 0:
                        a2.pop()
                        continue
                    coef = (a2[-1] * lc_inv) % p
                    deg = len(a2) - len(b)
                    for i in range(len(b)):
                        a2[deg+i] = (a2[deg+i] - coef * b[i]) % p
                    while a2 and a2[-1] == 0: a2.pop()
                if not a2: a2 = [0]
                a, b = b, a2
            return a

        g = pgcd(cs, xp_minus_x, prime)
        print(f"    gcd degree: {len(g)-1}")

        # Now factor g to get roots
        # g should be a product of distinct linear factors
        roots = []
        if len(g) <= 1:
            return roots
        if len(g) == 2:
            # g = g[0] + g[1]*x => root = -g[0]/g[1]
            roots.append((-g[0] * pow(g[1], -1, prime)) % prime)
            return roots

        # For higher degree, use Cantor-Zassenhaus or just try splitting
        import random
        random.seed(42)
        polys_to_factor = [g]
        while polys_to_factor:
            poly = polys_to_factor.pop()
            if len(poly) == 2:
                roots.append((-poly[0] * pow(poly[1], -1, prime)) % prime)
                continue
            if len(poly) <= 1:
                continue
            # Try random splitting
            for _ in range(100):
                r = random.randrange(prime)
                # gcd(poly, (x+r)^((p-1)/2) - 1)
                shifted = pm_pow([(r % prime), 1], (prime - 1) // 2, poly, prime)
                shifted[0] = (shifted[0] - 1) % prime
                while shifted and shifted[-1] == 0: shifted.pop()
                if not shifted: shifted = [0]

                h = pgcd(poly, shifted, prime)
                if 1 < len(h) < len(poly):
                    polys_to_factor.append(h)
                    # poly / h
                    q_poly = poly[:]
                    lc_inv = pow(h[-1], -1, prime)
                    while len(q_poly) >= len(h):
                        if q_poly[-1] == 0:
                            q_poly.pop()
                            continue
                        coef = (q_poly[-1] * lc_inv) % prime
                        deg = len(q_poly) - len(h)
                        for i in range(len(h)):
                            q_poly[deg+i] = (q_poly[deg+i] - coef * h[i]) % prime
                        while q_poly and q_poly[-1] == 0: q_poly.pop()
                    if q_poly and q_poly != [0]:
                        polys_to_factor.append(q_poly)
                    break

        return roots

    roots_p = poly_roots_mod_prime(f0, p)
    roots_q = poly_roots_mod_prime(f0, q)
    print(f"  Roots mod p: {len(roots_p)} found")
    print(f"  Roots mod q: {len(roots_q)} found")

    # CRT and check
    for rp in roots_p:
        for rq in roots_q:
            # CRT: x = rp mod p, x = rq mod q
            y0_cand = (rp * q * pow(q, -1, p) + rq * p * pow(p, -1, q)) % N

            # Verify: y_1 = c[0] - y0_cand >= 0 and < N
            y1_cand = c[0] - y0_cand
            if y1_cand < 0 or y1_cand >= N:
                continue

            # Verify: y_2 = c[1] - y1_cand >= 0 and < N
            y2_cand = c[1] - y1_cand
            if y2_cand < 0 or y2_cand >= N:
                continue

            # Verify modular relation: y1^4 = y0^3 * y2 mod N
            if pow(y1_cand, 4, N) != (pow(y0_cand, 3, N) * y2_cand) % N:
                continue

            print(f"\n  Valid y0 found: {y0_cand}")

            # Recover all y_i
            y = [y0_cand]
            for k in range(13):
                y.append(c[k] - y[k])

            # Verify all
            ok = True
            for k in range(14):
                if y[k] < 0 or y[k] >= N:
                    ok = False
                    break
            if not ok:
                print("    y values out of range, skip")
                continue

            # Common modulus attack: find e_i, e_j with gcd(e_i, e_j) small
            # Try gcd of first few pairs
            for i in range(14):
                for j in range(i+1, 14):
                    g = gcd(e[i], e[j])
                    if g == 1:
                        print(f"  gcd(e[{i}], e[{j}]) = 1, using common modulus attack")
                        # Extended GCD
                        def extended_gcd(a, b):
                            if a == 0: return b, 0, 1
                            g, x1, y1 = extended_gcd(b % a, a)
                            return g, y1 - (b // a) * x1, x1

                        _, a, b = extended_gcd(e[i], e[j])
                        # m = y[i]^a * y[j]^b mod N
                        # a or b might be negative
                        if a < 0:
                            m_part_i = pow(pow(y[i], -1, N), -a, N)
                        else:
                            m_part_i = pow(y[i], a, N)
                        if b < 0:
                            m_part_j = pow(pow(y[j], -1, N), -b, N)
                        else:
                            m_part_j = pow(y[j], b, N)

                        m = (m_part_i * m_part_j) % N
                        flag = long_to_bytes(m)
                        print(f"  m = {m}")
                        print(f"  flag = {flag}")
                        if b'flag' in flag.lower() or b'DH{' in flag or b'kalmar' in flag.lower():
                            print(f"\n*** FLAG FOUND: {flag.decode(errors='replace')} ***")
                        exit()

            # If no gcd=1 pair, use factored N to decrypt directly
            print("  No coprime exponent pair found. Using factored N.")
            phi = (p - 1) * (q - 1)
            for i in range(14):
                g = gcd(e[i], phi)
                if g == 1:
                    d = pow(e[i], -1, phi)
                    m = pow(y[i], d, N)
                    flag = long_to_bytes(m)
                    print(f"  Decrypted with e[{i}]: {flag}")
                    if b'flag' in flag.lower() or b'DH{' in flag or b'kalmar' in flag.lower():
                        print(f"\n*** FLAG FOUND: {flag.decode(errors='replace')} ***")
                    exit()
                else:
                    print(f"    gcd(e[{i}], phi) = {g}")

    print("No valid solution found via factored N path")

elif result:
    deg = len(result) - 1
    print(f"  GCD polynomial degree: {deg}")
    print(f"  GCD coefficients: {result}")

    if deg == 1:
        # Linear: result[0] + result[1]*x = 0 => x = -result[0] / result[1]
        y0 = (-result[0] * pow(result[1], -1, N)) % N
        print(f"  y0 = {y0}")

        # Recover all y_i
        y = [y0]
        for k in range(13):
            y.append(c[k] - y[k])

        # Verify
        for k in range(14):
            assert 0 <= y[k] < N, f"y[{k}] = {y[k]} out of range!"

        # Verify modular relations
        K = (y[1] * pow(y[0], -1, N) ** 3) % N  # Actually K = y[1] * inv(y[0])^3
        # Wait, need to be more careful
        # y[1] = y[0]^3 * K mod N => K = y[1] * y[0]^{-3} mod N
        K = (y[1] * pow(pow(y[0], 3, N), -1, N)) % N
        print(f"  K = {K}")

        # Common modulus attack
        for i in range(14):
            for j in range(i+1, 14):
                g = gcd(e[i], e[j])
                if g == 1:
                    print(f"  gcd(e[{i}], e[{j}]) = 1")
                    def extended_gcd(a, b):
                        if a == 0: return b, 0, 1
                        g, x1, y1 = extended_gcd(b % a, a)
                        return g, y1 - (b // a) * x1, x1

                    _, a, b = extended_gcd(e[i], e[j])
                    if a < 0:
                        m_i = pow(pow(y[i], -1, N), -a, N)
                    else:
                        m_i = pow(y[i], a, N)
                    if b < 0:
                        m_j = pow(pow(y[j], -1, N), -b, N)
                    else:
                        m_j = pow(y[j], b, N)

                    m = (m_i * m_j) % N
                    flag = long_to_bytes(m)
                    print(f"  flag = {flag}")
                    if b'flag' in flag.lower() or b'DH{' in flag or b'kalmar' in flag.lower():
                        print(f"\n*** FLAG FOUND: {flag.decode(errors='replace')} ***")
                    exit()

        print("  No coprime exponent pair found via common modulus.")

    elif deg == 0:
        print("  Polynomials are coprime mod N - no common root.")
        print("  Trying more equation pairs...")

        for k in range(2, 12):
            fk = make_eq(k)
            res2, fac2 = poly_gcd(f0, fk)
            if fac2:
                print(f"  Found factor from eq pair (0, {k}): {fac2}")
                break
            if res2 and len(res2) > 1:
                print(f"  GCD with eq {k}: degree {len(res2)-1}")
                break
    else:
        print(f"  GCD degree {deg} > 1, need further factoring")
        # Try to find roots by factoring the GCD polynomial
else:
    print("Something went wrong")
