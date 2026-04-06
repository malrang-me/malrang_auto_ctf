#!/usr/bin/env python3
"""RSA Attack Dispatcher — CTF Template
Copy to challenges/<name>/solve.py and fill in params below.
Tries attacks in priority order; prints flag on success.
Dependencies: gmpy2, pycryptodome, requests
"""

import math
import sys
from itertools import combinations

import gmpy2
from Crypto.Util.number import long_to_bytes

# ============================================================
# FILL IN PARAMETERS (set to None if unknown)
# ============================================================
n = None          # modulus (single or list for multi-key)
e = 65537         # public exponent
ct = None         # ciphertext (int)
dp = None         # d mod (p-1), CRT leak
dq = None         # d mod (q-1), CRT leak
phi = None        # Euler's totient, if leaked
p = None          # known factor
q = None          # known factor
ns = []           # list of moduli for common-factor attack
cts = []          # corresponding ciphertexts
primes = []       # list of primes for multi-prime RSA
FLAG_FMT = None   # e.g. b"flag{", b"DH{", b"CTF{" — None = accept any
# ============================================================


class RSAAttacker:
    def __init__(self, n=None, e=65537, ct=None, dp=None, dq=None,
                 phi=None, p=None, q=None, ns=None, cts=None,
                 primes=None, flag_fmt=None):
        self.n = n
        self.e = e
        self.ct = ct
        self.dp = dp
        self.dq = dq
        self.phi = phi
        self.p = p
        self.q = q
        self.ns = ns or []
        self.cts = cts or []
        self.primes = primes or []
        self.flag_fmt = flag_fmt

    # ----------------------------------------------------------
    # Core decrypt helper
    # ----------------------------------------------------------
    def _decrypt(self, p, q, e, ct, n=None):
        """Compute d from p,q,e and decrypt ct. Returns plaintext bytes."""
        n = n or p * q
        assert p * q == n, f"p*q != n  (diff={p*q - n})"
        phi = (p - 1) * (q - 1)
        d = int(gmpy2.invert(e, phi))
        pt = pow(ct, d, n)
        return long_to_bytes(pt)

    def _decrypt_multi(self, primes, e, ct):
        """CRT-based decrypt for multi-prime RSA."""
        from functools import reduce
        n = reduce(lambda a, b: a * b, primes)
        phi = reduce(lambda a, b: a * b, (p - 1 for p in primes))
        d = int(gmpy2.invert(e, phi))
        pt = pow(ct, d, n)
        return long_to_bytes(pt)

    def _is_flag(self, data):
        """Check if decrypted data looks like a flag."""
        if self.flag_fmt:
            return self.flag_fmt in data
        # Heuristic: printable ASCII with common flag wrappers
        try:
            text = data.decode("ascii", errors="ignore")
            wrappers = ["flag{", "FLAG{", "ctf{", "CTF{", "DH{", "dh{",
                         "pico{", "HTB{", "SECCON{", "ASIS{"]
            for w in wrappers:
                if w in text:
                    return True
            # Accept if mostly printable
            printable = sum(32 <= b < 127 for b in data)
            return printable > len(data) * 0.85 and len(data) >= 4
        except Exception:
            return False

    def _log(self, attack, msg):
        print(f"[{attack}] {msg}")

    # ----------------------------------------------------------
    # Attack 1: Small public exponent (eth root)
    # ----------------------------------------------------------
    def _try_small_e(self):
        if self.e is None or self.e > 17 or self.ct is None:
            return None
        self._log("small_e", f"Trying integer {self.e}th root of ct")
        root, exact = gmpy2.iroot(gmpy2.mpz(self.ct), self.e)
        if exact:
            pt = long_to_bytes(int(root))
            self._log("small_e", f"Exact root found: {pt[:40]}...")
            return pt
        # Try with small multiples of n (ct + k*n)
        if self.n:
            for k in range(1, 10000):
                root, exact = gmpy2.iroot(gmpy2.mpz(self.ct + k * self.n), self.e)
                if exact:
                    pt = long_to_bytes(int(root))
                    if self._is_flag(pt):
                        self._log("small_e", f"Root found at k={k}: {pt[:40]}...")
                        return pt
        return None

    # ----------------------------------------------------------
    # Attack 2: dp/dq leak
    # ----------------------------------------------------------
    def _try_dp_dq(self):
        if self.dp is None or self.n is None or self.e is None:
            return None
        self._log("dp_dq", "Recovering p from dp leak")
        # p = GCD(pow(2, dp*(e-1), n) - 1, n)
        val = pow(2, self.dp * (self.e - 1), self.n) - 1
        p = math.gcd(val, self.n)
        if 1 < p < self.n:
            q = self.n // p
            assert p * q == self.n
            self._log("dp_dq", f"Factored! p={str(p)[:30]}... q={str(q)[:30]}...")
            return self._decrypt(p, q, self.e, self.ct)
        # Try with dq if dp didn't work
        if self.dq is not None:
            self._log("dp_dq", "dp failed, trying dq")
            val = pow(2, self.dq * (self.e - 1), self.n) - 1
            p = math.gcd(val, self.n)
            if 1 < p < self.n:
                q = self.n // p
                assert p * q == self.n
                return self._decrypt(p, q, self.e, self.ct)
        return None

    # ----------------------------------------------------------
    # Attack 3: Known phi (totient)
    # ----------------------------------------------------------
    def _try_phi_known(self):
        if self.phi is None or self.n is None:
            return None
        self._log("phi_known", "Factoring n from known phi via quadratic formula")
        # n = p*q, phi = (p-1)(q-1) = n - p - q + 1
        # So p + q = n - phi + 1, p * q = n
        s = self.n - self.phi + 1  # p + q
        # p and q are roots of x^2 - s*x + n = 0
        disc = s * s - 4 * self.n
        if disc < 0:
            return None
        sqrt_disc, exact = gmpy2.iroot(gmpy2.mpz(disc), 2)
        if not exact:
            return None
        p = int((s + sqrt_disc) // 2)
        q = int((s - sqrt_disc) // 2)
        if p * q == self.n:
            self._log("phi_known", f"Factored! p={str(p)[:30]}... q={str(q)[:30]}...")
            return self._decrypt(p, q, self.e, self.ct)
        return None

    # ----------------------------------------------------------
    # Attack 4: Common factor across multiple moduli
    # ----------------------------------------------------------
    def _try_common_factor(self):
        if len(self.ns) < 2:
            return None
        self._log("common_factor", f"Checking GCD of {len(self.ns)} moduli")
        for i, j in combinations(range(len(self.ns)), 2):
            g = math.gcd(self.ns[i], self.ns[j])
            if 1 < g < self.ns[i]:
                p = g
                q = self.ns[i] // p
                self._log("common_factor", f"Common factor between n[{i}] and n[{j}]!")
                ct_i = self.cts[i] if i < len(self.cts) else self.ct
                return self._decrypt(p, q, self.e, ct_i)
        return None

    # ----------------------------------------------------------
    # Attack 5: FactorDB lookup
    # ----------------------------------------------------------
    def _try_factordb(self):
        if self.n is None:
            return None
        self._log("factordb", "Querying factordb.com...")
        try:
            import requests
            resp = requests.get(
                f"http://factordb.com/api",
                params={"query": str(self.n)},
                timeout=15,
            )
            data = resp.json()
            status = data.get("status", "")
            # status: "FF" = fully factored, "CF" = composite fully factored
            if status in ("FF", "CF", "P"):
                factors_raw = data.get("factors", [])
                factors = []
                for base, exp in factors_raw:
                    factors.extend([int(base)] * int(exp))
                if len(factors) == 2:
                    p, q = factors
                    self._log("factordb", f"Factored! p={str(p)[:30]}... q={str(q)[:30]}...")
                    return self._decrypt(p, q, self.e, self.ct)
                elif len(factors) > 2:
                    self._log("factordb", f"Multi-prime: {len(factors)} factors")
                    return self._decrypt_multi(factors, self.e, self.ct)
            else:
                self._log("factordb", f"Not factored (status={status})")
        except Exception as ex:
            self._log("factordb", f"Error: {ex}")
        return None

    # ----------------------------------------------------------
    # Attack 6: Wiener's attack (large e / small d)
    # ----------------------------------------------------------
    def _try_wiener(self):
        if self.n is None or self.e is None or self.ct is None:
            return None
        # Only useful when e is large relative to n
        if self.e < self.n // 3:
            return None
        self._log("wiener", "Trying continued fraction attack for small d")

        def continued_fraction(a, b):
            cf = []
            while b:
                cf.append(a // b)
                a, b = b, a % b
            return cf

        def convergents(cf):
            h0, h1 = 0, 1
            k0, k1 = 1, 0
            for q in cf:
                h0, h1 = h1, q * h1 + h0
                k0, k1 = k1, q * k1 + k0
                yield h1, k1

        cf = continued_fraction(self.e, self.n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            if (self.e * d - 1) % k != 0:
                continue
            phi_candidate = (self.e * d - 1) // k
            # Check: x^2 - (n - phi + 1)x + n = 0 has integer roots
            s = self.n - phi_candidate + 1
            disc = s * s - 4 * self.n
            if disc < 0:
                continue
            sqrt_disc, exact = gmpy2.iroot(gmpy2.mpz(disc), 2)
            if exact:
                p = int((s + sqrt_disc) // 2)
                q = int((s - sqrt_disc) // 2)
                if p * q == self.n:
                    self._log("wiener", f"Found d={d}, factored n!")
                    return self._decrypt(p, q, self.e, self.ct)
        return None

    # ----------------------------------------------------------
    # Attack 7: Fermat factorization (close primes)
    # ----------------------------------------------------------
    def _try_fermat(self):
        if self.n is None:
            return None
        self._log("fermat", "Trying Fermat factorization (close primes)")
        a = gmpy2.isqrt(self.n) + 1
        b2 = a * a - self.n
        for _ in range(1_000_000):
            b, exact = gmpy2.iroot(b2, 2)
            if exact:
                p = int(a + b)
                q = int(a - b)
                if p * q == self.n and q > 1:
                    self._log("fermat", f"Factored! p={str(p)[:30]}... q={str(q)[:30]}...")
                    return self._decrypt(p, q, self.e, self.ct)
            a += 1
            b2 = a * a - self.n
        self._log("fermat", "No close factors found within limit")
        return None

    # ----------------------------------------------------------
    # Attack 8: Multi-prime RSA (primes already known)
    # ----------------------------------------------------------
    def _try_multi_prime(self):
        if len(self.primes) < 2 or self.ct is None:
            return None
        self._log("multi_prime", f"Decrypting with {len(self.primes)} known primes via CRT")
        from functools import reduce
        n_check = reduce(lambda a, b: a * b, self.primes)
        if self.n:
            assert n_check == self.n, "Product of primes != n"
        return self._decrypt_multi(self.primes, self.e, self.ct)

    # ----------------------------------------------------------
    # Known factors shortcut
    # ----------------------------------------------------------
    def _try_known_factors(self):
        if self.p and self.q and self.ct is not None:
            self._log("known", "Using provided p, q")
            return self._decrypt(self.p, self.q, self.e, self.ct)
        return None

    # ----------------------------------------------------------
    # Auto attack dispatcher
    # ----------------------------------------------------------
    def auto_attack(self):
        """Run all attacks in priority order. Returns flag bytes or None."""
        attacks = [
            ("known_factors", self._try_known_factors),
            ("small_e",       self._try_small_e),
            ("dp_dq",         self._try_dp_dq),
            ("phi_known",     self._try_phi_known),
            ("common_factor", self._try_common_factor),
            ("factordb",      self._try_factordb),
            ("wiener",        self._try_wiener),
            ("fermat",        self._try_fermat),
            ("multi_prime",   self._try_multi_prime),
        ]

        for name, attack_fn in attacks:
            try:
                result = attack_fn()
                if result and self._is_flag(result):
                    print(f"\n{'='*60}")
                    print(f"FLAG FOUND via [{name}]")
                    flag = result.decode("latin-1").strip("\x00")
                    print(f"  {flag}")
                    print(f"{'='*60}")
                    return result
                elif result:
                    print(f"[{name}] Decrypted but doesn't look like flag: {result[:60]}")
            except Exception as ex:
                print(f"[{name}] Error: {ex}")

        print("\n[!] All attacks exhausted. No flag found.")
        print("    Consider: Coppersmith (sage), Boneh-Durfee, Hastad broadcast,")
        print("    padding oracle, or challenge-specific algebraic relations.")
        return None


def main():
    attacker = RSAAttacker(
        n=n, e=e, ct=ct, dp=dp, dq=dq,
        phi=phi, p=p, q=q,
        ns=ns, cts=cts, primes=primes,
        flag_fmt=FLAG_FMT,
    )
    result = attacker.auto_attack()
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
