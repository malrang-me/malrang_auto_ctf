# Challenge Index

> malrang_auto_ctf Knowledge Base

## Solved Challenges

| Challenge | Category | Platform | Level | Key Technique | File |
|-----------|----------|----------|-------|---------------|------|
| RSA Quartet | Crypto | Dreamhack | 5 | enc(-k) trick, oracle | [rsa_quartet.md](challenges/rsa_quartet.md) |
| Perfect RSA | Crypto | Dreamhack | 6 | Coppersmith partial key | [perfect_rsa.md](challenges/perfect_rsa.md) |
| Glitchy Sig | Crypto | Dreamhack | 6 | Fault attack | [glitchy_sig.md](challenges/glitchy_sig.md) |
| Not So Smart | Crypto | Dreamhack | 6 | Smart's attack (anomalous curve) | [not_so_smart.md](challenges/not_so_smart.md) |
| 이것도 딸깍해 보시지! | Misc | Dreamhack | 1 | PDF text extraction trap (anti-AI) | [ddalgak.md](challenges/ddalgak.md) |
| Times | Reversing | Dreamhack | 4 | bit_reverse_32 self-inverse, time gate LD_PRELOAD, XOR keystream cancellation | [Times.md](challenges/Times.md) |
| playing-with-login | Web | Dreamhack | 4 | MariaDB uca1400_ai_ci accent-insensitive collation confusion + v2 abort side-effect | [playing-with-login.md](challenges/playing-with-login.md) |

| baby-turbofan | Pwn (V8) | Dreamhack | - | TurboFan Math.expm1 타입혼동 → OOB → AAR/AAW → WASM RWX | [baby-turbofan.md](challenges/baby-turbofan.md) |
| GoN 2022 Collection | Multi | Dreamhack | - | 15문제 일괄 학습 (A~V) | [GoN2022_collection.md](challenges/GoN2022_collection.md) |
| GoN 2022F Collection | Multi | Dreamhack | - | 5문제 출제자 라이트업 (F~J) | [GoN2022F_collection.md](challenges/GoN2022F_collection.md) |

## Learned (Writeup Study)

| Challenge | Category | Platform | Level | Key Technique | File |
|-----------|----------|----------|-------|---------------|------|
| RBG+++ | Crypto | Dreamhack/KalmarCTF | 10 | LLL + algebraic number theory + polynomial GCD | [rbg_plus_plus_plus.md](challenges/rbg_plus_plus_plus.md) |
| lance-hard? | Crypto | KalmarCTF 2025 | - | Wagner's Birthday + Semaev polynomials | (referenced in rbg_plus_plus_plus.md) |

## Attempted (Unsolved)

| Challenge | Category | Platform | Level | Blocker | File |
|-----------|----------|----------|-------|---------|------|
| Schnorsa | Crypto | Dreamhack | 6 | DLP 512-bit + nonce XOR | [schnorsa.md](challenges/schnorsa.md) |

## Techniques Library

See `techniques/` directory:
- [efficient_solving.md](techniques/efficient_solving.md) — Problem classification + approach selection
- [v8_turbofan_exploitation.md](techniques/v8_turbofan_exploitation.md) — V8 TurboFan JIT exploitation (Math.expm1, OOB, WASM RWX)
- [prototype_pollution.md](techniques/prototype_pollution.md) — JS Prototype Pollution (__proto__, constructor.prototype)
- [timing_attack.md](techniques/timing_attack.md) — Timing side-channel attack (byte/block comparison)
- [gdb_scripting.md](techniques/gdb_scripting.md) — GDB Python scripting for brute-force reversing
- [web_exploit_chains.md](techniques/web_exploit_chains.md) — Web exploit chains (LFI+CSRF+SQLi, CTR reuse)
- [ssrf_tls_session_poisoning.md](techniques/ssrf_tls_session_poisoning.md) — SSRF via TLS Session ID + DNS rebinding + Memcached
- [pickle_deserialization.md](techniques/pickle_deserialization.md) — Python pickle deserialization bypass techniques
- [redis_exploitation.md](techniques/redis_exploitation.md) — Redis RCE (CVE-2021-32761, jemalloc hooks, config write)
- [qemu_vm_escape.md](techniques/qemu_vm_escape.md) — QEMU VM escape via DMA MMIO reentrancy
- [tls_dtv_exploitation.md](techniques/tls_dtv_exploitation.md) — glibc TLS overflow → DTV → heap exploitation
- [race_condition_toctou.md](techniques/race_condition_toctou.md) — TOCTOU race condition (/proc leak, fd reuse)
- [lll_algebraic_number_poly.md](techniques/lll_algebraic_number_poly.md) — LLL + algebraic number theory for modular exponent equations
