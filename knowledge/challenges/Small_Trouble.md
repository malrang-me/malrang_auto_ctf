# Small_Trouble
## Category: crypto
## Technique: Wiener's attack (small private exponent)
## Summary
Standard RSA with an unusually large public exponent e (roughly the same size as n), indicating a correspondingly small private exponent d. Wiener's attack via continued fraction expansion of e/n efficiently recovers d by finding it among the convergents.

## Approach
1. Noticed that e is extremely large (close to n in size), which is the classic signal for Wiener's attack -- d must be small.
2. Computed the continued fraction expansion of e/n.
3. Iterated through convergents (k/d candidates).
4. For each candidate d: checked if (e*d - 1) is divisible by k, computed phi = (e*d - 1)/k, derived p+q from n and phi, and verified via the discriminant that p and q are valid integers with p*q = n.
5. Once valid d found, decrypted c directly: m = c^d mod n.

## Key Code
```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import isqrt, is_square

def continued_fraction(num, den):
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def convergents(cf):
    convs = []
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for a in cf:
        h2 = a * h1 + h0
        k2 = a * k1 + k0
        convs.append((h2, k2))
        h0, h1 = h1, h2
        k0, k1 = k1, k2
    return convs

cf = continued_fraction(e, n)
for k, d in convergents(cf):
    if k == 0: continue
    if (e * d - 1) % k != 0: continue
    phi = (e * d - 1) // k
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc >= 0 and is_square(disc):
        sqrt_disc = isqrt(disc)
        p, q = (s + sqrt_disc) // 2, (s - sqrt_disc) // 2
        if p * q == n:
            m = pow(c, d, n)
            print(f"Flag: {long_to_bytes(m).decode()}")
            break
```

## Lessons
- When e is close to n in bit-length, immediately suspect Wiener's attack (small d).
- The continued fraction method is fast and deterministic -- no brute force needed.
- Wiener's attack works when d < n^0.25 / 3. The large e is the primary detection signal.
- Always verify the candidate d by checking p*q == n before attempting decryption.
