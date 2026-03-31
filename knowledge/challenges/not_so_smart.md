# Not So Smart | Crypto | Dreamhack

- **Level**: 6
- **Date**: 2026-03-29
- **Flag**: `DH{n0T_50_5m4rt_cURv3_b34t3D}`
- **Status**: Solved

## Summary

ECDH key exchange on an anomalous elliptic curve (curve order = p). Smart's attack recovers the private key in O(1) via p-adic lifting.

## Key Facts

- p = 0x91f7989d5e019623425111dc87c6341898974a4286dd6080d23994ac7b39f0b7
- Curve: y^2 = x^3 + ax + b over GF(p)
- #E(GF(p)) == p (anomalous)
- Shared secret = (m*P).x, used as AES-CBC key via SHA256

## Attack: Smart's Attack

1. Verify curve is anomalous: p * G == O (point at infinity)
2. Lift points G, Q from E(GF(p)) to E(Z/p^2Z) using Hensel lifting
3. Compute p-adic elliptic logarithm: log(Q_lift) / log(G_lift) mod p = m
4. Compute shared_secret = (m * P).x
5. Decrypt AES-CBC with SHA256(shared_secret)[:16]

## Solver

`challenges/Not_So_Smart/solve.py` — pure Python implementation of Smart's attack with p-adic arithmetic (no SageMath dependency).

## References

- Smart's attack on anomalous curves (Nigel Smart, 1999)
- p-adic lifting technique for ECDLP when #E = p
