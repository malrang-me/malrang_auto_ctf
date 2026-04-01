# ClusterRSA
## Category: crypto
## Technique: Multi-prime RSA factorization
## Summary
RSA challenge where n is composed of 4 close primes (multi-prime RSA) rather than the standard 2 primes. The modulus n is small enough (~100 digits) that sympy's `factorint` can factor it directly, after which standard RSA decryption with generalized Euler's totient recovers the flag.

## Approach
1. Observed that n is relatively small (~330 bits), suggesting it can be factored directly.
2. Used `sympy.factorint(n)` to factor n into its 4 prime components.
3. Computed Euler's totient: phi = product of (p_i - 1) * p_i^(exp_i - 1) for each prime factor.
4. Computed RSA private key d = e^(-1) mod phi.
5. Decrypted: m = ct^d mod n, then converted to bytes.

## Key Code
```python
from Crypto.Util.number import long_to_bytes
from sympy import factorint

n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 3891158515405030211396309867177046660195995913985068178988858029936868358096672572274111514200511662

factors = factorint(n)
phi = 1
for p, exp in factors.items():
    phi *= (p - 1) * (p ** (exp - 1))

d = pow(e, -1, phi)
m = pow(ct, d, n)
flag = long_to_bytes(m)
print(f"Flag: {flag.decode()}")
```

## Lessons
- When n is small (under ~400 bits), always try direct factorization first -- sympy or yafu can handle it quickly.
- Multi-prime RSA with 4 close primes of similar size is a strong signal for direct factoring.
- The generalized totient formula for multi-prime RSA is phi = product of (p_i - 1) * p_i^(e_i - 1), which reduces to product of (p_i - 1) when all exponents are 1.
