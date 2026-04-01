# Schnorsa
## Category: crypto
## Technique: Schnorr-RSA hybrid with leaked phi + DLP recovery
## Summary
A Schnorr-like signature scheme over RSA composites where the server leaks phi(n) as part of the public key. This allows factoring n, computing the RSA private key, recovering nonces from signatures via RSA decryption, solving the discrete log modulo each prime factor via Pohlig-Hellman/sympy, and finally recovering the secret key x from the signature equation.

## Approach
1. Connected to the remote server and received the public key (e, phi, n, y) where phi is leaked.
2. Factored n using phi: p + q = n - phi + 1, then solved the quadratic x^2 - (p+q)x + n = 0.
3. Computed RSA private key d = e^(-1) mod phi.
4. Requested a signature on message m=0. Got (r, s) where r = (t << nb | msg)^e mod n.
5. Recovered t = g^k mod n by RSA-decrypting r: t_msg = r^d mod n, then t = t_msg >> nb.
6. Solved the discrete log k such that g^k = t mod p and g^k = t mod q using sympy's discrete_log (Pohlig-Hellman internally).
7. Combined results via CRT to get k mod lcm(p-1, q-1).
8. Recovered x from signature equation: s = k + x*r mod phi, so x = (s - k) * r^(-1) mod phi.
9. Verified pow(g, x, n) == y and submitted x to get the flag.

## Key Code
```python
def factor_from_phi(n, phi):
    s = n - phi + 1
    disc = gmpy2.isqrt(s*s - 4*n)
    p = (s + disc) // 2
    q = (s - disc) // 2
    assert p * q == n
    return int(p), int(q)

# Recover nonce from signature
d = int(gmpy2.invert(e, phi))
t_msg = pow(r, d, n)
t = t_msg >> nb

# Solve DLP mod each factor
from sympy.ntheory.residues import discrete_log as sympy_dlog
k_p = sympy_dlog(p, t % p, g % p)
k_q = sympy_dlog(q, t % q, g % q)

# CRT combine and recover secret
k = crt([p-1, q-1], [k_p, k_q])[0]
r_inv = int(gmpy2.invert(r, phi))
x = ((s - k) * r_inv) % phi
```

## Lessons
- Leaking phi(n) in an RSA-based scheme is fatal: it allows immediate factoring via the quadratic formula on p+q and p*q.
- When nonces are derived from a GF(2)-linear generator (XOR/shift), multiple signatures can constrain the nonce space. Z3 bitvector solving and GF(2) matrix methods were explored as alternatives but the direct DLP approach was simpler.
- For DLP mod composite n, decompose into DLP mod p and mod q, solve each with Pohlig-Hellman (works when p-1 or q-1 have smooth factors), then CRT-combine.
- Three different solver approaches were attempted: (1) direct DLP via sympy (solve.py -- the winning approach), (2) Z3 bitvector constraints on nonce generator (z3_solve.py), and (3) GF(2) linearization of nonce generator + Pohlig-Hellman partial DLP (gf2_solve.py). The direct approach won because sympy handles Pohlig-Hellman internally when factor orders are smooth enough.
