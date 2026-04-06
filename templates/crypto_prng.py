#!/usr/bin/env python3
"""PRNG attack templates for CTF challenges.

Classes:
- MT19937Cloner: clone Mersenne Twister from 624 outputs
- LCGSolver: recover LCG parameters from outputs
- LFSRSolver: Berlekamp-Massey algorithm for LFSR

Pure Python, no external dependencies beyond standard library.
"""

import random
from math import gcd
from functools import reduce


class MT19937Cloner:
    """Clone Python's random.Random (MT19937) from 624 consecutive 32-bit outputs."""

    @staticmethod
    def untemper(y: int) -> int:
        """Reverse MT19937 tempering transform.

        MT19937 tempering (forward):
            y ^= y >> 11
            y ^= (y << 7) & 0x9D2C5680
            y ^= (y << 15) & 0xEFC60000
            y ^= y >> 18
        """
        # Reverse y ^= y >> 18
        y ^= y >> 18

        # Reverse y ^= (y << 15) & 0xEFC60000
        y ^= (y << 15) & 0xEFC60000  # only bottom 15 bits survive shift

        # Reverse y ^= (y << 7) & 0x9D2C5680 (iterative, 7 bits at a time)
        tmp = y
        for i in range(4):
            tmp = y ^ ((tmp << 7) & 0x9D2C5680)
        y = tmp

        # Reverse y ^= y >> 11 (iterative, 11 bits at a time)
        tmp = y
        for i in range(2):
            tmp = y ^ (tmp >> 11)
        y = tmp

        return y & 0xFFFFFFFF

    @classmethod
    def clone(cls, outputs: list) -> random.Random:
        """Clone MT19937 state from exactly 624 consecutive 32-bit outputs.

        Args:
            outputs: list of 624 consecutive getrandbits(32) values

        Returns:
            random.Random instance with cloned state
        """
        assert len(outputs) >= 624, f"Need 624 outputs, got {len(outputs)}"

        mt_state = [cls.untemper(o) for o in outputs[:624]]

        # Reconstruct internal state tuple: (3, tuple(624 ints + index), None)
        cloned = random.Random()
        state = (3, tuple(mt_state + [624]), None)
        cloned.setstate(state)
        return cloned

    @classmethod
    def predict(cls, outputs: list, n: int) -> list:
        """Predict next n outputs after observing 624 values.

        Args:
            outputs: list of 624 consecutive getrandbits(32) values
            n: number of future values to predict

        Returns:
            list of n predicted 32-bit values
        """
        rng = cls.clone(outputs)
        return [rng.getrandbits(32) for _ in range(n)]

    @classmethod
    def clone_from_randint(cls, outputs: list, lo: int, hi: int) -> random.Random:
        """Clone from randint(lo, hi) outputs when range fits 32 bits.

        For randint with range <= 2^32, each call consumes one 32-bit word.
        This is a simplified case; wider ranges consume multiple words.
        """
        rng_range = hi - lo + 1
        assert rng_range <= 2**32, "Range too wide for simple recovery"
        # For power-of-2 ranges, output = getrandbits(k) + lo
        # For non-power-of-2, rejection sampling complicates things
        # This works best when rng_range is a power of 2
        raw = [o - lo for o in outputs]
        return cls.clone(raw)


class LCGSolver:
    """Recover LCG parameters: x_{n+1} = a*x_n + b (mod m)."""

    @staticmethod
    def solve(outputs: list, modulus: int = None) -> tuple:
        """Recover LCG parameters (a, b, m) from consecutive outputs.

        Args:
            outputs: at least 6 consecutive LCG outputs
                     (3 if modulus known, 6 if unknown)
            modulus: known modulus (None to auto-detect)

        Returns:
            (a, b, m): multiplier, increment, modulus
        """
        assert len(outputs) >= 3, "Need at least 3 outputs"

        if modulus is None:
            modulus = LCGSolver._recover_modulus(outputs)
            if modulus is None:
                raise RuntimeError("Cannot recover modulus; provide more outputs or known modulus")

        m = modulus

        # Recover multiplier a: (x2 - x1) * inverse(x1 - x0) mod m
        x0, x1, x2 = outputs[0], outputs[1], outputs[2]
        diff1 = (x1 - x0) % m
        diff2 = (x2 - x1) % m

        if gcd(diff1, m) != 1:
            # Try later outputs
            for i in range(len(outputs) - 2):
                diff1 = (outputs[i + 1] - outputs[i]) % m
                diff2 = (outputs[i + 2] - outputs[i + 1]) % m
                if gcd(diff1, m) == 1:
                    x0, x1 = outputs[i], outputs[i + 1]
                    break
            else:
                raise RuntimeError("Cannot find coprime difference for modulus")

        a = (diff2 * pow(diff1, -1, m)) % m
        b = (x1 - a * x0) % m

        # Verify
        for i in range(len(outputs) - 1):
            assert (a * outputs[i] + b) % m == outputs[i + 1], \
                f"Verification failed at index {i}"

        return (a, b, m)

    @staticmethod
    def _recover_modulus(outputs: list) -> int:
        """Recover modulus from 6+ outputs using GCD of determinants.

        Uses the identity: if t_n = x_{n+1} - x_n, then
        t_{n+1}*t_{n-1} - t_n^2 = 0 (mod m)
        """
        assert len(outputs) >= 6, "Need at least 6 outputs to recover modulus"

        diffs = [outputs[i + 1] - outputs[i] for i in range(len(outputs) - 1)]
        # t_{i+1}*t_{i-1} - t_i^2 should be 0 mod m
        zeros = []
        for i in range(1, len(diffs) - 1):
            val = diffs[i + 1] * diffs[i - 1] - diffs[i] * diffs[i]
            if val != 0:
                zeros.append(abs(val))

        if not zeros:
            return None

        m = reduce(gcd, zeros)

        # m might be a multiple of the actual modulus; try to reduce
        if m < 2:
            return None

        # Factor out small primes if m seems too large
        for p in [2, 3, 5, 7, 11, 13]:
            while m % p == 0 and m // p > max(outputs):
                m //= p

        return m

    @staticmethod
    def predict(outputs: list, n: int, modulus: int = None) -> list:
        """Predict next n outputs."""
        a, b, m = LCGSolver.solve(outputs, modulus)
        predictions = []
        x = outputs[-1]
        for _ in range(n):
            x = (a * x + b) % m
            predictions.append(x)
        return predictions


class LFSRSolver:
    """LFSR analysis via Berlekamp-Massey algorithm."""

    @staticmethod
    def berlekamp_massey(bits: list) -> list:
        """Berlekamp-Massey algorithm over GF(2).

        Finds the shortest LFSR that generates the given bit sequence.

        Args:
            bits: list of 0/1 values (need >= 2*L bits where L is LFSR length)

        Returns:
            coefficients: list of tap positions [c1, c2, ...] such that
                         s[n] = c1*s[n-1] XOR c2*s[n-2] XOR ...
        """
        n = len(bits)
        # Current connection polynomial C(x), previous B(x)
        C = [1]
        B = [1]
        L = 0  # current LFSR length
        m = 1  # steps since last length change
        b = 1  # previous discrepancy

        for i in range(n):
            # Compute discrepancy
            d = bits[i]
            for j in range(1, L + 1):
                if j < len(C):
                    d ^= C[j] & bits[i - j]

            if d == 0:
                m += 1
            elif 2 * L <= i:
                # Length change needed
                T = list(C)
                # C(x) = C(x) - d*b^{-1} * x^m * B(x)
                # Over GF(2): d=b=1, so C ^= shift(B, m)
                shift_B = [0] * m + B
                while len(C) < len(shift_B):
                    C.append(0)
                for j in range(len(shift_B)):
                    C[j] ^= shift_B[j]
                L = i + 1 - L
                B = T
                b = d
                m = 1
            else:
                shift_B = [0] * m + B
                while len(C) < len(shift_B):
                    C.append(0)
                for j in range(len(shift_B)):
                    C[j] ^= shift_B[j]
                m += 1

        # Return tap coefficients (skip C[0] which is always 1)
        return C[1:L + 1]

    @staticmethod
    def predict(bits: list, n: int) -> list:
        """Predict next n bits from observed LFSR output.

        Args:
            bits: observed bit sequence (at least 2*LFSR_length)
            n: number of bits to predict

        Returns:
            list of predicted bits
        """
        taps = LFSRSolver.berlekamp_massey(bits)
        L = len(taps)
        assert L > 0, "Could not determine LFSR structure"

        state = list(bits[-L:])  # last L bits as initial state
        predictions = []

        for _ in range(n):
            # next bit = XOR of tapped positions
            new_bit = 0
            for j, c in enumerate(taps):
                if c:
                    new_bit ^= state[-(j + 1)]
            predictions.append(new_bit)
            state.append(new_bit)

        return predictions

    @staticmethod
    def find_period(bits: list) -> int:
        """Estimate the period of an LFSR from its output."""
        taps = LFSRSolver.berlekamp_massey(bits)
        L = len(taps)
        # Maximum period of an L-bit LFSR is 2^L - 1
        return (1 << L) - 1


# ============================================================
# Usage Examples
# ============================================================

if __name__ == '__main__':
    # --- MT19937 Cloner ---
    print("=== MT19937 Cloner Test ===")
    rng = random.Random(42)
    outputs = [rng.getrandbits(32) for _ in range(624)]
    expected = [rng.getrandbits(32) for _ in range(10)]

    cloned = MT19937Cloner.clone(outputs)
    predicted = [cloned.getrandbits(32) for _ in range(10)]
    assert predicted == expected, "MT19937 clone failed"
    print("[+] MT19937 clone: OK")

    # --- LCG Solver ---
    print("\n=== LCG Solver Test ===")
    m, a, b = 2**31 - 1, 16807, 12345
    x = 1
    lcg_out = []
    for _ in range(8):
        x = (a * x + b) % m
        lcg_out.append(x)
    a_r, b_r, m_r = LCGSolver.solve(lcg_out)
    assert a_r == a and b_r == b and m_r == m, "LCG solve failed"
    print(f"[+] LCG recovered: a={a_r}, b={b_r}, m={m_r}")

    # --- LFSR Berlekamp-Massey ---
    print("\n=== LFSR Solver Test ===")
    # 4-bit LFSR: s[n] = s[n-1] XOR s[n-4]
    state = [1, 0, 1, 1]
    bits = list(state)
    for _ in range(30):
        new = bits[-1] ^ bits[-4]
        bits.append(new)
    taps = LFSRSolver.berlekamp_massey(bits)
    print(f"[+] LFSR taps: {taps}")
    pred = LFSRSolver.predict(bits[:20], 14)
    assert pred == bits[20:34], "LFSR prediction failed"
    print("[+] LFSR prediction: OK")
