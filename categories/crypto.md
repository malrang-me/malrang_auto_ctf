# CRYPTO — Cryptography

## MCP Tools
- **solver-z3**: Z3 SMT solver | **solver-pysat**: PySAT | **solver-cryptominisat**: CryptoMiniSat (CRC, linear crypto)
- **sage-helper**: SymPy (factor, GF, mod_inverse, matrix) | **py-repl**: gmpy2, pycryptodome
- **WSL**: `wsl sage` for full SageMath

## Attack Patterns

### RSA
- Small e + small message → cube root / Coppersmith (small_roots)
- Common p → GCD of moduli
- Weak key → factordb, RsaCtfTool, yafu
- Wiener (small d) → continued fractions
- Hastad broadcast → CRT + nth root
- Bleichenbacher → padding oracle PKCS#1 v1.5
- Partial key exposure → Coppersmith multivariate
- Multi-prime → factor each, CRT decryption
- dp/dq leak → p = GCD(pow(2, dp*(e-1), n) - 1, n)

### AES
- ECB → block substitution, byte-at-a-time oracle
- CBC → bit flipping, padding oracle
- CTR → nonce reuse = XOR plaintexts
- GCM → nonce reuse = recover auth key via polynomial GCD

### Elliptic Curve
- Small order → Pohlig-Hellman
- Anomalous (trace=1) → Smart's attack
- MOV → Weil pairing reduces to finite field DLP
- Invalid curve → small subgroup attack
- Singular → map to additive/multiplicative group

### Hash
- Length extension → SHA1/SHA256/MD5 (NOT SHA3/HMAC)
- Collision → birthday, chosen-prefix
- CRC → linear algebra over GF(2)

### PRNG / Stream
- MT19937 → 624 outputs to clone; untemper
- LCG → known outputs recover a, b, m
- LFSR → Berlekamp-Massey from 2n bits
- XOR → frequency analysis, known plaintext

### Lattice
- LLL → knapsack, HNP, CVP/SVP
- Coppersmith → small roots mod N (SageMath small_roots)
- NTRU → lattice reduction

### Number Theory
- Discrete log → Pohlig-Hellman (smooth), BSGS, index calculus
- CRT → combine modular equations

## Token-Efficient Tool Chain (IDA급 절감 도구)
```bash
# RsaCtfTool: 수동 sage 스크립팅 23k tok → 자동 1줄 5k tok (78% 절감)
wsl python3 ~/RsaCtfTool/RsaCtfTool.py -n <N> -e <e> --uncipher <c> --attack all
# easy RSA는 이것만으로 풀림. solver 에이전트 스폰도 불필요할 수 있음.

# factordb: 수동 factor 시도 → 즉시 인수분해 (있으면)
# sage-helper: pow(c,d,n) 한 줄로 복호화 (수동 추론 500tok → 20tok)
```

## Pitfalls
- NEVER do modular arithmetic in head — use sage-helper/py-repl.
- gmpy2 for large int modular exp (faster than sympy).
- Verify factorization: `assert p * q == n`.
- MT19937: exactly 624 consecutive 32-bit values, untempered correctly.
- Coppersmith: check epsilon and beta carefully.
- Remote oracle: batch queries to reduce latency.

## Subtype Detection (triage.py auto-classification)
triage.py가 `crypto_subtype`을 자동 감지. solver/crypto-solver 프롬프트에 주입됨.

| Subtype | 핵심 시그널 | 추천 템플릿 | Decision Tree Trigger |
|---------|-----------|------------|----------------------|
| rsa | pow(m,e,n), getPrime, bytes_to_long | crypto_rsa.py | rsa_attack |
| ecc | EllipticCurve, discrete_log, ECDSA | crypto_ecc.sage | ecc_attack |
| lattice | LLL, BKZ, small_roots, Coppersmith | crypto_lattice.sage | lattice_attack |
| symmetric | AES, CBC, ECB, padding, oracle | crypto_oracle.py | symmetric_attack / oracle_attack |
| prng | MT19937, LCG, LFSR, random | crypto_prng.py | prng_attack |
| hash | SHA, MD5, HMAC, length_extension | — | hash_crack |

## SageMath Workflow
**sage-helper MCP** = SymPy backend. `small_roots`, `LLL`, `EllipticCurve` **불가**.
이것들이 필요하면 반드시 **`wsl sage`** 사용.

```bash
# 간단한 연산: sage-helper MCP
sage-helper: pow(c, d, n)
sage-helper: factor(12345)

# 복잡한 연산: wsl sage
wsl sage solve.sage 2>&1
```

### sage-helper vs wsl sage
| sage-helper (OK) | wsl sage (필수) |
|------------------|-----------------|
| pow, factor(small), mod_inverse | small_roots, Coppersmith |
| CRT, gcd, lcm | LLL, BKZ, Matrix(ZZ) |
| GF basic ops | EllipticCurve, discrete_log |
| | Weil pairing, p-adic lift |

### .sage 파일 실행 패턴
```bash
# 1. 템플릿 복사 + 파라미터 수정
cp templates/crypto_lattice.sage challenges/<name>/solve.sage
# 2. 실행
wsl sage challenges/<name>/solve.sage 2>&1
# 3. 실패 시 epsilon/beta/block_size 조정 후 재실행
```

## Templates (사용법)
```bash
# RSA (Python): 파라미터 채우고 실행
cp templates/crypto_rsa.py challenges/<name>/solve.py
python challenges/<name>/solve.py

# Lattice (Sage): 파라미터 채우고 wsl sage
cp templates/crypto_lattice.sage challenges/<name>/solve.sage
wsl sage challenges/<name>/solve.sage

# Oracle (Python+pwntools): host/port + oracle 로직 수정
cp templates/crypto_oracle.py challenges/<name>/solve.py

# ECC (Sage): curve params 채우기
cp templates/crypto_ecc.sage challenges/<name>/solve.sage

# PRNG (Python): output values 채우기
cp templates/crypto_prng.py challenges/<name>/solve.py
```

## Pre-screening (Easy Win)
```bash
# RSA easy check: factordb, small e, dp/dq, phi
python tools/crypto_prescreen.py challenges/<name>
# Returns: {"solved": true, "flag": "...", "method": "..."} or {"solved": false}
```

## Advanced (L4+ only — load via triage.py when needed)
- Post-quantum/LWE: BDD/uSVP, Kannan embedding
- EHNP: multi-sample HNP with modular constraints
- Coppersmith variants: Herrmann-May multivariate
- Lattice ECDSA: biased nonce Bleichenbacher-style
- Hybrid: Coppersmith + LLL, MITM + SAT, Grobner basis
