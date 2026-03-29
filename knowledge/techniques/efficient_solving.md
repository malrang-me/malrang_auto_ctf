# Efficient Solving Patterns

## Problem Type Classification

| Type | Detection Signal | First Approach | Fallback |
|------|-----------------|----------------|----------|
| RSA (small e/d/phi leak) | n, e, phi in output | Factor n via phi, compute d | Wiener/Boneh-Durfee |
| RSA (CRT fault) | Faulty signatures | GCD with n | Bellcore attack |
| ECC (invalid curve) | Custom curve params | Invalid curve attack | Smart's attack |
| PRNG (LCG/PCG) | Sequential outputs | State recovery + predict | Z3 bitvec |
| Lattice (HNP/CVP) | Partial info leak | LLL/BKZ reduction | Coppersmith |
| AES-ECB | Block-aligned oracle | Byte-at-a-time | Cut-and-paste |
| AES-CBC | Padding oracle | Padding oracle attack | Bit-flipping |
| Hash (length ext) | MAC = H(secret\|\|msg) | Length extension | HashPump |
| Schnorr/ECDSA (nonce) | Biased/reused nonce | HNP lattice | Bleichenbacher |
| Custom cipher | Feistel/SPN structure | Differential/linear | Meet-in-middle |
| Format string | printf(user_input) | %n writes, %p leaks | GOT overwrite |
| Buffer overflow | gets/strcpy/sprintf | ROP chain | ret2libc |
| Heap (UAF/double free) | malloc/free patterns | tcache poison | fastbin dup |
| Web (SQLI) | SQL error in response | Union/blind injection | sqlmap |
| Web (SSTI) | Template reflection | Jinja2/Twig RCE | Sandbox escape |

## MCP Tool Selection

| Problem | MCP Tool | When |
|---------|----------|------|
| SMT/constraint | solver-z3 | Exact constraints, bitvec ops |
| SAT (boolean) | solver-pysat | Pure boolean satisfiability |
| CNF with XOR | solver-cryptominisat | Crypto with XOR constraints |
| Symbolic math | sage-helper | Factor, discrete_log, GF, lattice |
| General compute | py-repl | Prototyping, data processing |
| Binary analysis | pwn-local | checksec, readelf, objdump, ROPgadget |
| IDA decompile | ida-pro-mcp | When IDA Pro is running |

## Speed Patterns (from solved challenges)

### RSA with phi leaked
1. Factor n: p+q = n-phi+1, solve quadratic → p,q
2. d = e^(-1) mod phi
3. Decrypt/sign as needed
**Time: <30 seconds**

### Schnorr nonce reuse
1. Two sigs with same k: x = (s1-s2)/(r1-r2) mod q
**Time: <10 seconds**

### LCG state recovery
1. Collect 3+ outputs
2. Compute: a = (s2-s3)/(s1-s2) mod m, b = s2-a*s1 mod m
**Time: <1 minute**
