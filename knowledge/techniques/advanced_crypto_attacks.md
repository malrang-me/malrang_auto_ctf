# Advanced Crypto CTF Techniques - Research Compilation

Compiled from 2022-2025 CTF writeups and academic sources.
Use as a reference when encountering these problem families.

---

## 1. Coppersmith Small Roots (Stereotyped Messages, Partial Key Recovery)

### 1A. Stereotyped Message Attack

**Source Challenge**: squ1rrel CTF 2024 - "Partial RSA"
**CTF Event**: squ1rrel CTF 2024

**Problem Structure**:
- Given: RSA ciphertext ct, public key (n, e) with small e (typically e=3 or e=5)
- Flag format known: e.g. `squ1rrel{XXXXXXXXX}` with unknown bytes in the middle
- Goal: recover the full plaintext

**Key Mathematical Insight**:
- If you know a large prefix of the plaintext m, write m = m_known + x where x is small
- Construct polynomial f(x) = (m_known + x)^e - ct (mod n)
- Coppersmith's theorem: if |x| < N^(1/e), we can find x in polynomial time via LLL
- The smaller e is, the larger the unknown portion can be

**Attack Chain**:
1. Convert known flag prefix to integer m_known
2. Construct polynomial ring over Zmod(n)
3. Define f(x) = (m_known + x)^e - ct
4. Call small_roots() with appropriate bounds
5. Iterate over possible flag lengths if unknown

**Reusable SageMath Pattern**:
```python
# SageMath
n, e, ct = ...  # given values
prefix = b"squ1rrel{"
suffix = b"}"

for flag_len in range(1, 100):
    m_known = int.from_bytes(prefix + b"\x00" * flag_len + suffix, "big")
    P.<x> = PolynomialRing(Zmod(n))
    # unknown bytes start after prefix, before suffix
    shift = (len(suffix)) * 8
    f = (m_known + x * 2^shift)^e - ct
    roots = f.small_roots(X=256^flag_len, beta=1, epsilon=1/30)
    if roots:
        unknown = int(roots[0])
        flag = prefix + unknown.to_bytes(flag_len, "big") + suffix
        print(flag)
        break
```

**Common Failure Patterns**:
- WRONG: Not iterating over possible flag lengths -> no roots found
- WRONG: epsilon too large -> LLL lattice dimension too small, misses root
- WRONG: Using beta < 1 when factoring is not needed (stereotyped = full modulus)
- WRONG: Byte ordering mistakes (big-endian vs little-endian)
- FIX: Start with epsilon=1/30 or smaller; increase lattice dimension if needed
- FIX: Verify m_known construction by checking known-plaintext case first

### 1B. Partial Key Exposure (Known High Bits of p)

**Source Challenges**: Crypto CTF 2021 "Polish", Tokyo Westerns CTF 2017 "BabyRSA", UMD CTF 2024 "Key Recovery"

**Problem Structure**:
- Given: RSA modulus n = p*q, and partial information about p (e.g., top half of bits)
- Goal: factor n completely

**Key Mathematical Insight**:
- Coppersmith (1996): given the top half of bits of p (for an n-bit prime), you can recover full p
- Write p = p_high + x where p_high is the known MSBs and x < 2^(nbits/2)
- f(x) = p_high + x has a small root modulo p, and p | n

**Attack Chain**:
1. Extract known MSBs of p -> p_high
2. P.<x> = PolynomialRing(Zmod(n))
3. f = p_high + x
4. roots = f.small_roots(X=2^unknown_bits, beta=0.5)
5. p = p_high + roots[0]; q = n // p

**Reusable SageMath Pattern**:
```python
# SageMath - partial p recovery
n = ...
p_high = ...  # known MSBs, low bits zeroed
unknown_bits = 512  # number of unknown LSBs

P.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5, epsilon=0.02)
if roots:
    p = int(p_high + roots[0])
    assert n % p == 0
    q = n // p
    # Now decrypt with p, q
```

**Common Failure Patterns**:
- WRONG: beta != 0.5 for partial p (beta represents the proportion of n that p is)
- WRONG: Not enough known bits (need > 50% for degree-1 polynomial)
- WRONG: p_high not properly zero-padded in low bits
- FIX: For dp/dq leaks, first compute partial p via: p = gcd(pow(2, e*dp - 1, n) - 1, n)
- FIX: If standard small_roots fails, try Howgrave-Graham's reformulation or increase epsilon

### 1C. Partial dp Leak

**Problem Structure**:
- Given: n, e, ct, and partial dp (d mod p-1)

**Attack Chain**:
1. For each candidate k in range(1, e): p_candidate = (e * dp_partial - 1 + k) / k
2. Check if n % p_candidate == 0
3. If dp is partially known, use Coppersmith on f(x) = e*(dp_known + x) - 1 (mod p) with beta=0.5

---

## 2. Lattice Dimension/Bound Design (HNP Variants, Knapsack)

### 2A. Hidden Number Problem (HNP) - ECDSA Nonce Bias

**Source Challenge**: Crypto CTF 2024 - "Honey" (Extended HNP), HITCON CTF 2024 - "ECLCG"

**Problem Structure**:
- Given: ECDSA signatures (r_i, s_i) where nonces k_i have some bias (known MSBs, LSBs, or bounded range)
- Known: public key Q, message hashes h_i, curve order q
- Goal: recover private key d

**Key Mathematical Insight (HNP)**:
- ECDSA: s_i = k_i^(-1) * (h_i + d * r_i) mod q
- Rearranging: k_i = s_i^(-1) * h_i + s_i^(-1) * r_i * d mod q
- Let t_i = s_i^(-1) * r_i mod q, a_i = s_i^(-1) * h_i mod q
- Then: k_i = a_i + t_i * d mod q
- If we know partial k_i information, this is exactly HNP
- Construct CVP/SVP instance and use LLL/BKZ to solve

**Attack Chain (Kannan Embedding for CVP -> SVP)**:
1. Collect n signatures with biased nonces
2. Build lattice basis B (dimension n+2):
```
B = [  q  0  0  ...  0  0  0 ]
    [  0  q  0  ...  0  0  0 ]
    [ t1 t2 t3  ... tn  B/q 0 ]
    [ a1 a2 a3  ... an  0  B ]
```
   where B = 2^(bits_known) is the bound on the unknown nonce portion
3. Apply LLL/BKZ reduction to B
4. Find short vector; extract d from the result

**Reusable SageMath Pattern**:
```python
# SageMath - ECDSA HNP with known MSBs
from sage.all import *

def ecdsa_hnp_attack(signatures, q, known_bits):
    """
    signatures: list of (r, s, h, k_msb) tuples
    q: curve order
    known_bits: number of known MSBs of nonce
    """
    n = len(signatures)
    B_bound = 2^(256 - known_bits)  # bound on unknown portion

    # Build lattice
    M = Matrix(QQ, n + 2, n + 2)

    for i in range(n):
        r, s, h, k_partial = signatures[i]
        t = (inverse_mod(s, q) * r) % q
        a = (inverse_mod(s, q) * h) % q
        M[i, i] = q
        M[n, i] = t
        M[n+1, i] = a - k_partial  # subtract known portion

    M[n, n] = B_bound / q
    M[n+1, n+1] = B_bound

    L = M.LLL()

    # Extract d from short vectors
    for row in L:
        d_candidate = int(row[n] * q / B_bound) % q
        if d_candidate > 0:
            # Verify
            r0, s0, h0, _ = signatures[0]
            k_check = (inverse_mod(s0, q) * (h0 + d_candidate * r0)) % q
            if k_check < 2^256:
                return d_candidate
    return None
```

**Crypto CTF 2024 "Honey" Specifics**:
- Used Extended HNP variant
- Upper bound: sqrt(p) * 2^34 (from Hlavac-Rosa 2007 theorem 3)
- Applied Kannan embedding to convert CVP to SVP

**Common Failure Patterns**:
- WRONG: Lattice dimension too small -> LLL cannot find short enough vector
- WRONG: Incorrect bound B -> target vector not shortest
- WRONG: Not enough signatures (need ~ceil(256/known_bits) signatures minimum)
- WRONG: Using LLL when BKZ with higher block size needed for tight bounds
- FIX: Minimum signatures: n >= ceil(bitsize / known_bits) + small constant
- FIX: Try BKZ with block_size=25-40 if LLL fails
- FIX: Scale lattice columns to balance row norms

### 2B. ECDSA with LCG Nonces

**Source Challenge**: HITCON CTF 2024 - "ECLCG"

**Attack Chain**:
1. Model nonces as k_i = a * k_{i-1} + b mod q (LCG relation)
2. Build lattice basis using Stern's construction to annihilate each nonce
3. LLL on the lattice recovers all nonces directly
4. From any nonce, recover private key: d = (s*k - h) * r^(-1) mod q

### 2C. Knapsack / Low-Density Attack

**Problem Structure**:
- Given: public knapsack sequence a_1, ..., a_n and target sum S
- Goal: find binary vector x such that sum(a_i * x_i) = S

**Key Insight**:
- If density d = n / log2(max(a_i)) < 0.9408, CJLOSS lattice attack works
- Build lattice with identity matrix and knapsack weights, apply LLL

**Reusable Pattern**:
```python
# SageMath - low density knapsack attack (CJLOSS)
def knapsack_lll(weights, target):
    n = len(weights)
    N = ceil(sqrt(n) / 2)  # scaling factor

    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = N * weights[i]
    M[n, n] = N * (-target)

    L = M.LLL()
    for row in L:
        if row[n] == 0:
            solution = [int(row[i]) for i in range(n)]
            if all(b in [0, 1] for b in solution):
                return solution
    # Try with negated solution
    for row in L:
        if row[n] == 0:
            solution = [int(-row[i]) for i in range(n)]
            if all(b in [0, 1] for b in solution):
                return solution
    return None
```

---

## 3. Elliptic Curve Advanced Attacks

### 3A. MOV Attack (Weil Pairing)

**Source Challenge**: Cyber Apocalypse CTF 2022 - "MOVs Like Jagger"

**Problem Structure**:
- Given: supersingular elliptic curve E over GF(p), generator G, public point Q = d*G
- Goal: recover scalar d (ECDLP)
- Key condition: curve has SMALL embedding degree k (k <= 6, often k=2 for supersingular)

**Key Mathematical Insight**:
- The Weil pairing e_m maps pairs of m-torsion points to m-th roots of unity in GF(p^k)
- e_m(Q, R) = e_m(d*G, R) = e_m(G, R)^d
- This converts ECDLP on E to DLP in GF(p^k)*, which is solvable by index calculus if k is small
- For supersingular curves over GF(p), embedding degree is always 1, 2, 3, 4, or 6

**Attack Chain**:
1. Verify curve is supersingular: #E(GF(p)) = p + 1 (for embedding degree 2)
2. Compute embedding degree k: smallest k such that m | (p^k - 1)
3. Extend to GF(p^k) and find linearly independent point R in E[m]
4. Compute alpha = e_m(G, R) and beta = e_m(Q, R)
5. Solve DLP: d = discrete_log(beta, alpha) in GF(p^k)*

**Reusable SageMath Pattern**:
```python
# SageMath - MOV attack
def mov_attack(E, G, Q, p, order):
    # Find embedding degree
    k = 1
    while (p^k - 1) % order != 0:
        k += 1

    # Extend field
    Ek = E.change_ring(GF(p^k, 'a'))
    Gk = Ek(G)
    Qk = Ek(Q)

    # Find independent point R
    while True:
        R = Ek.random_point()
        R = (R.order() // order) * R  # ensure R has same order
        if R != Ek(0) and Gk.weil_pairing(R, order) != 1:
            break

    # Compute pairings
    alpha = Gk.weil_pairing(R, order)
    beta = Qk.weil_pairing(R, order)

    # Solve DLP in finite field
    d = discrete_log(beta, alpha)
    return d
```

**Detection Signals**:
- Curve order = p + 1 (supersingular, embedding degree 2)
- Curve defined over GF(p) with p = 3 mod 4 and a = 0
- Small group order relative to field size

**Common Failure Patterns**:
- WRONG: Not finding correct embedding degree -> extending to wrong field
- WRONG: Random point R is in same subgroup as G -> pairing is trivial (= 1)
- FIX: Ensure R is linearly independent from G (pairing != 1)
- FIX: For large k, DLP in GF(p^k)* may still be hard; check k <= 6

### 3B. Invalid Curve Attack

**Source Challenge**: Business CTF 2022 - "400 Curves"

**Problem Structure**:
- Given: ECDH server that computes scalar multiplication d * P for arbitrary point P
- Server does NOT validate that P lies on the curve E
- Goal: recover server's private scalar d

**Key Mathematical Insight**:
- A point not on curve E(a,b) may lie on a different curve E(a,b') with smooth order
- Montgomery ladder / x-only arithmetic computes correctly regardless of which curve the point is on
- If the "wrong" curve has smooth order, you can recover d mod (small prime factors) via Pohlig-Hellman
- CRT all partial recoveries to get full d

**Attack Chain**:
1. For various b' values, compute order of E(a, b') over GF(p)
2. Find b' values where the order is smooth (has only small prime factors)
3. For each small prime factor l_i of a smooth-order curve:
   a. Find a point P_i of order l_i on E(a, b'_i)
   b. Send P_i to server, receive Q_i = d * P_i
   c. Solve small ECDLP: d mod l_i = discrete_log(Q_i, P_i)
4. CRT all (d mod l_i) to recover d

**Reusable Pattern**:
```python
# SageMath - invalid curve attack
from sage.all import *

def invalid_curve_attack(p, a, oracle_func, target_bits=256):
    """
    oracle_func(Px, Py) -> (Qx, Qy) : computes d * P
    """
    residues = []
    moduli = []
    bits_recovered = 0

    b_candidate = 1
    while bits_recovered < target_bits:
        b_candidate += 1
        E_fake = EllipticCurve(GF(p), [a, b_candidate])
        order = E_fake.order()
        factors = factor(order)

        for (l, _) in factors:
            if l < 2^20 and l not in moduli:  # small primes only
                # Find point of order l
                P = E_fake.random_point()
                P = (order // l) * P
                if P == E_fake(0):
                    continue

                Qx, Qy = oracle_func(int(P[0]), int(P[1]))
                Q = E_fake(Qx, Qy)

                # Small ECDLP
                d_mod_l = discrete_log(Q, P, ord=l, operation='+')
                residues.append(d_mod_l)
                moduli.append(l)
                bits_recovered += log(l, 2)

    d = CRT_list(residues, moduli)
    return d
```

**Common Failure Patterns**:
- WRONG: Server returns error for off-curve points -> attack not applicable
- WRONG: Forgetting that some curves over GF(p) have no points of desired order
- WRONG: Not handling the case where Q is point at infinity
- FIX: Pre-screen b' candidates for smooth order before querying oracle
- FIX: Handle y-coordinate ambiguity if server returns x-only

### 3C. Twist Attack

**Source Challenge**: ECSC 2023 - "Twist and Shout"

**Problem Structure**:
- Server uses Montgomery ladder (x-coordinate only) for scalar multiplication
- No point validation (or only x-coordinate given)
- Goal: recover private scalar d

**Key Mathematical Insight**:
- Given x-coordinate only, the point is on either E or its quadratic twist E'
- Montgomery ladder computes correctly on BOTH E and E'
- If twist E' has smooth order, same approach as invalid curve attack
- Probability 1/2 that a random x lies on the twist

**Attack Chain**:
1. Compute twist curve parameters: E': by^2 = x^3 + ax^2 + x where b is a non-residue
2. Factor order of E'
3. If smooth, find points of small order on E' and query oracle
4. Recover d mod l_i for each small factor l_i via Pohlig-Hellman
5. CRT to recover d

**Detection Signals**:
- Montgomery curve (By^2 = x^3 + Ax^2 + x) or x-only ECDH
- No explicit point-on-curve validation
- Challenge name hints: "twist", "montgomery", "x-only"

**Common Failure Patterns**:
- WRONG: Computing twist order incorrectly (twist order = 2p + 2 - #E for curves over GF(p))
- WRONG: Not realizing both E and E' share the same x-only arithmetic
- FIX: #E' = 2*(p+1) - #E is the standard twist order relation
- FIX: Check SafeCurves twist security page for known-weak twist orders

### 3D. Smart's Attack (Anomalous Curves)

**Source Challenge**: GCC CTF 2024 - "Elliptic"

**Problem Structure**:
- Elliptic curve E over GF(p) where #E(GF(p)) = p (anomalous curve)
- Goal: solve ECDLP

**Key Insight**:
- Lift curve to Q_p (p-adic numbers), compute ECDLP via p-adic logarithm
- Runs in polynomial time for anomalous curves

**Attack Chain**:
1. Verify #E = p (anomalous)
2. Lift E to Q_p
3. Compute p-adic elliptic logarithm of lifted points
4. d = log_p(Q_lift) / log_p(G_lift) mod p

**Reusable SageMath Pattern**:
```python
def smart_attack(E, G, Q, p):
    """E over GF(p) with #E = p"""
    Qp = pAdicField(p, 20)
    Ep = EllipticCurve(Qp, [ZZ(a) + p*ZZ(0) for a in E.a_invariants()])

    Gp = Ep.lift_x(ZZ(G.xy()[0]))
    Qp_pt = Ep.lift_x(ZZ(Q.xy()[0]))

    # Ensure correct lift (matching y-coordinate sign)
    if GF(p)(Gp.xy()[1]) != G.xy()[1]:
        Gp = -Gp
    if GF(p)(Qp_pt.xy()[1]) != Q.xy()[1]:
        Qp_pt = -Qp_pt

    pGp = p * Gp
    pQp = p * Qp_pt

    x_G, y_G = pGp.xy()
    x_Q, y_Q = pQp.xy()

    phi_G = -(x_G / y_G)
    phi_Q = -(x_Q / y_Q)

    d = ZZ(phi_Q / phi_G) % p
    return d
```

---

## 4. Multi-Round Interactive Crypto Protocols

### 4A. RSA LSB/Parity Oracle (Adaptive CCA)

**Source Challenge**: HKCERT CTF 2023 - RSA Parity Oracle

**Problem Structure**:
- Given: RSA ciphertext ct = m^e mod n
- Oracle: accepts ciphertext, returns LSB of decrypted plaintext
- Goal: recover full plaintext m

**Key Mathematical Insight**:
- RSA is multiplicatively homomorphic: D(ct * 2^e mod n) = 2*m mod n
- If 2*m < n, LSB reveals parity of 2*m which gives information about m
- Each query halves the search space for m
- Need exactly ceil(log2(n)) queries to recover m completely

**Attack Chain**:
1. Start with bounds [lo, hi] = [0, n]
2. For each bit position i = 0, 1, ..., log2(n)-1:
   a. Compute blinding factor: f = pow(2, e*(i+1), n)
   b. Send ct' = ct * f mod n to oracle
   c. Get LSB bit b
   d. Update bounds: if b == 0, hi = (lo + hi) / 2; else lo = (lo + hi) / 2
3. m = hi (or lo)

**Reusable Python Pattern**:
```python
from pwn import *
from Crypto.Util.number import *

def lsb_oracle_attack(n, e, ct, oracle_func):
    """oracle_func(ct_bytes) -> int (0 or 1, the LSB)"""
    lo, hi = 0, n
    f = 1
    multiplier = pow(2, e, n)

    for i in range(n.bit_length()):
        f = (f * multiplier) % n
        ct_modified = (ct * f) % n

        bit = oracle_func(ct_modified)

        mid = (lo + hi) // 2  # integer division
        if bit == 0:
            hi = mid
        else:
            lo = mid

    return long_to_bytes(hi)
```

**Alternative**: Manger's Attack (for OAEP oracle returning padding validity)
- Requires only ~1100 queries instead of ~2048
- Uses multiplicative blinding with larger factors

### 4B. Bleichenbacher / PKCS#1 v1.5 Padding Oracle

**Source**: SECCON CTF 2022, DUCTF 2022, SekaiCTF 2022

**Problem Structure**:
- RSA with PKCS#1 v1.5 padding
- Oracle tells whether decrypted ciphertext has valid padding (starts with 0x0002)
- Goal: recover plaintext

**Key Insight**:
- Multiply ciphertext by s^e to get encryption of m*s mod n
- Binary search on s values to narrow down m range
- Conforming ciphertexts reveal that 2B <= m*s mod n < 3B where B = 2^(8*(k-2))

**Attack Chain**:
1. Find initial s_1: smallest s where oracle(ct * s^e mod n) = VALID
2. Narrow interval [a, b] using: a = ceil((2B + r*n) / s), b = floor((3B - 1 + r*n) / s)
3. Iterate: for each interval, find next conforming s
4. When interval width = 1, m is recovered

**Common Failure Patterns**:
- WRONG: Not handling multiple intervals in early rounds
- WRONG: Off-by-one in interval computation
- WRONG: Slow convergence from bad initial s choice
- FIX: Use optimized Bleichenbacher with trimming (reduces queries by 4x)
- FIX: Implement interval merging for efficiency

### 4C. Commitment Scheme Exploits

**Common Attack Patterns**:
1. **Hash-and-reveal with weak hash**: If commitment = H(value || nonce) and hash is weak (e.g., CRC, short hash), find collisions
2. **Non-binding commitment**: If commitment doesn't bind to value, adversary can open to different values
3. **Non-hiding commitment**: If commitment leaks information about value, break hiding property
4. **Length extension**: If commitment uses H(secret || msg), use length extension to forge new commitments

**Detection Signals**:
- Server commits then reveals, or asks you to commit
- Custom hash function in commitment
- Commitment opened multiple times or verified against multiple values

---

## 5. Isogeny-Based Crypto (SIDH/SIKE, Castryck-Decru)

### 5A. SIDH Protocol and the Castryck-Decru Attack

**Source Challenge**: RCTF 2022 - "S2DH"
**CTF Event**: RCTF 2022 (solved by 7/363 teams)

**Problem Structure**:
- Standard SIDH key exchange implemented
- Alice and Bob exchange j-invariants and torsion point images
- Goal: recover shared secret (j-invariant)

**Background on SIDH**:
- Based on walks in the supersingular isogeny graph
- Alice: secret isogeny phi_A of degree 2^a from E_0, publishes (E_A, phi_A(P_B), phi_A(Q_B))
- Bob: secret isogeny phi_B of degree 3^b from E_0, publishes (E_B, phi_B(P_A), phi_B(Q_A))
- Shared secret: j(E_AB) = j(E_BA)

**Key Mathematical Insight (Castryck-Decru 2022)**:
- The auxiliary torsion point images (phi_A(P_B), phi_A(Q_B)) leak enough information to recover Alice's secret isogeny
- Based on Kani's "reducibility criterion" for isogenies from products of elliptic curves
- Constructs a (2,2)-isogeny on the product E_A x E_0 using the leaked torsion images
- Recovers Alice's secret key in polynomial time

**Attack Chain**:
1. Parse SIDH public key: (E_A, phi_A(P_B), phi_A(Q_B))
2. Construct product surface E_A x E_0
3. Use Kani's lemma to construct gluing isogeny
4. Compute chain of (2,2)-isogenies on the product
5. Extract Alice's secret isogeny from the chain
6. Compute shared secret j-invariant
7. Decrypt flag (typically XOR or AES with derived key)

**Reusable Code Reference**:
- Primary implementation: github.com/GiacomoPope/Castryck-Decru-SageMath
- Requires SageMath >= 9.5
- Performance: SIKEp64 broken in ~10 seconds on laptop; SIKEp434 in ~1 hour

**Adapting to CTF**:
```python
# Typical CTF adaptation pattern
# 1. Parse challenge output to extract SIDH public keys
# 2. Map to Castryck-Decru parameter format
# 3. Run attack to recover j_invariant
# 4. Derive decryption key from j_invariant
# 5. Decrypt flag

# Key adaptation: challenge may use non-standard primes
# The attack works for any prime p = 2^a * 3^b * f - 1
# Modify prime and torsion parameters in the SageMath script
```

**RCTF 2022 "S2DH" Specifics**:
- Standard SIDH with XOR encryption
- Required modifying Castryck-Decru code for the specific curve parameters
- Flag: `RCTF{SIDH_isBr0ken_in_2O22}`

**Common Failure Patterns**:
- WRONG: Using SageMath < 9.5 (isogeny functions incompatible)
- WRONG: Not adapting prime parameters to match challenge
- WRONG: Incorrect torsion point parsing from challenge output
- FIX: Always verify E_0, torsion basis, and prime form before running attack
- FIX: Use the GiacomoPope implementation (has performance optimizations, 8x faster than naive)
- FIX: For non-standard parameters, check that 2^a and 3^b are close in size

### 5B. CryptoHack Isogeny Challenges (Educational)

**Platform**: CryptoHack (cryptohack.org/challenges/isogenies/)

**Topics Covered**:
- Supersingular isogeny graphs and random walks
- j-invariant computation and curve isomorphism
- Basic SIDH implementation
- Attack mechanics post Castryck-Decru

**Learning Path**:
1. Understand j-invariant and isomorphism classes
2. Implement basic isogeny computation
3. Build SIDH key exchange
4. Apply Castryck-Decru attack

---

## Quick Reference: Detection Signal -> Attack Mapping

| Signal | Attack | Section |
|--------|--------|---------|
| Small e (3,5), known plaintext prefix | Coppersmith stereotyped | 1A |
| Partial bits of p/q leaked | Coppersmith partial key | 1B |
| dp or dq partially known | Coppersmith on dp | 1C |
| ECDSA + biased nonces | HNP lattice attack | 2A |
| ECDSA + LCG nonces | Stern lattice attack | 2B |
| Knapsack / subset sum | Low-density LLL | 2C |
| Supersingular curve, #E = p+1 | MOV attack | 3A |
| ECDH no point validation | Invalid curve attack | 3B |
| Montgomery / x-only ECDH | Twist attack | 3C |
| #E = p (anomalous) | Smart's attack | 3D |
| RSA oracle returns 1 bit | LSB oracle / parity | 4A |
| RSA PKCS#1 padding oracle | Bleichenbacher | 4B |
| Custom commitment scheme | Binding/hiding break | 4C |
| SIDH with torsion images | Castryck-Decru | 5A |

---

## Source References

### Topic 1 - Coppersmith
- [squ1rrel CTF 2024 - Partial RSA](https://nightxade.github.io/ctf-writeups/writeups/2024/squ1rrel-CTF-2024/crypto/partial-rsa.html)
- [UMD CTF 2024 - Key Recovery](https://connor-mccartney.github.io/cryptography/rsa/Key-Recovery-UMD-CTF-2024)
- [Practical CTF - RSA Attacks](https://book.jorianwoltjer.com/cryptography/asymmetric-encryption/rsa)
- [RSA-and-LLL-attacks (mimoo)](https://github.com/mimoo/RSA-and-LLL-attacks)
- [RSA Coppersmith Stereotyped Message (maximmasiutin)](https://github.com/maximmasiutin/rsa-coppersmith-stereotyped-message)

### Topic 2 - Lattice / HNP
- [Crypto CTF 2024 - Honey](https://ctftime.org/writeup/39180)
- [HITCON CTF 2024 - ECLCG](https://connor-mccartney.github.io/cryptography/ecc/ECLCG-HITCON-2024)
- [Gentle Tutorial for Lattice-Based Cryptanalysis (Surin & Cohney 2023)](https://eprint.iacr.org/2023/032.pdf)
- [FCSC 2024 Crypto Writeups](https://bitsdeep.com/posts/fcsc-2024-write-ups-for-the-crypto-challenges/)
- [CryptoHack - ECDSA Side Channel Attack](https://blog.cryptohack.org/ecdsa-side-channel-attack-projective-signatures-donjon-ctf-writeup)

### Topic 3 - Elliptic Curve Attacks
- [Cyber Apocalypse 2022 - MOVs Like Jagger](https://www.hackthebox.com/blog/movs-like-jagger-ca-ctf-2022-crypto-writeup)
- [ECSC 2023 - Twist and Shout](https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout/)
- [Business CTF 2022 - 400 Curves](https://www.hackthebox.com/blog/business-ctf-2022-400-curves-write-up)
- [GCC CTF 2024 - Elliptic (Smart's Attack)](https://connor-mccartney.github.io/cryptography/ecc/Elliptic-GCC-CTF-2024)
- [ECC Attacks Collection](https://github.com/elikaski/ECC_Attacks)
- [Invalid Curve Attack Implementation](https://github.com/forensicskween/invalid-curve-attack)

### Topic 4 - Interactive Protocols
- [HKCERT CTF 2023 - RSA Parity Oracle](https://mystiz.hk/posts/2024/2024-01-27-hkcert-ctf-2/)
- [Generalized Bleichenbacher Attack](https://github.com/tl2cents/Generalized-Bleichenbacher-Attack)
- [BSides Canberra CTF 2024 - PSI Protocol](https://thesavageteddy.github.io/featured/bsides-canberra-ctf-2024/)

### Topic 5 - Isogeny
- [RCTF 2022 - S2DH](https://ctftime.org/writeup/36033)
- [Castryck-Decru SageMath Implementation](https://github.com/GiacomoPope/Castryck-Decru-SageMath)
- [NCC Group - Implementing Castryck-Decru](https://www.nccgroup.com/research-blog/implementing-the-castryck-decru-sidh-key-recovery-attack-in-sagemath/)
- [Reimplementation Notes (eprint 2022/1283)](https://eprint.iacr.org/2022/1283)
- [CryptoHack Isogeny Challenges](https://cryptohack.org/challenges/isogenies/)
