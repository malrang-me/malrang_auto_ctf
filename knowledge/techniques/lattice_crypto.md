# Lattice-Based Cryptanalysis

## When to Use Lattice
- Partial information leak (MSB/LSB of secret)
- Biased nonces in signatures (ECDSA/Schnorr)
- Small roots of polynomial (Coppersmith)
- Hidden Number Problem (HNP)
- Knapsack-based ciphers

## LLL/BKZ Quick Reference

### Setup (SageMath)
```python
M = matrix(ZZ, [
    [N, 0, 0],
    [a, 1, 0],
    [b, 0, K],
])
L = M.LLL()
# Short vector in L[0] or L[1]
```

### Scaling
- Balance row norms: multiply columns by appropriate powers of 2
- Target vector length ~ det(L)^(1/n) by Minkowski bound
- If target >> Minkowski bound, LLL will find it

## Common CTF Patterns

### HNP (Hidden Number Problem)
Given: t_i * alpha - beta_i is small (mod p)
Find: alpha

```python
# n equations, each with ~k bits unknown
n = len(samples)
B = matrix(ZZ, n+2, n+2)
B[0,0] = p
for i in range(n):
    B[i+1,0] = t[i]
    B[i+1,i+1] = 1
B[n+1,0] = sum(beta)  # or individual betas
B[n+1,n+1] = 2^k
L = B.LLL()
```

### Coppersmith Small Roots
```python
# Find small root x0 of f(x) = 0 mod N
P.<x> = PolynomialRing(Zmod(N))
f = x^e + ... # polynomial
roots = f.small_roots(X=2^k, beta=0.5)
```

### Biased Nonce Attack (ECDSA/Schnorr)
If nonce k has known MSBs or is biased:
```python
# Collect multiple signatures (r_i, s_i, m_i)
# s_i = k_i^(-1) * (m_i + r_i * x) mod q
# k_i = a_i + 2^l * b_i where b_i is known (or small)
# Rewrite as HNP and solve with LLL
```

### Knapsack / Subset Sum
```python
# Given weights w_i and target S, find binary x_i
M = matrix(ZZ, n+1, n+1)
for i in range(n):
    M[i,i] = 1
    M[i,n] = w[i]
M[n,n] = -S
L = M.LLL()
# Solution vector has entries in {0,1,-1}
```

## Precondition Checks (before running LLL)
1. Dimension n <= 300 (larger = slow, may not converge)
2. Bit advantage: need enough known/small bits vs unknown
3. Gaussian heuristic: target vector < det^(1/n) * sqrt(n/(2*pi*e))
4. If preconditions fail: try BKZ with larger block size, or different formulation
