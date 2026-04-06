#!/usr/bin/env sage
"""
crypto_lattice.sage — SageMath lattice attack library for CTF challenges.
Usage: wsl sage crypto_lattice.sage
Import in other .sage files: load("templates/crypto_lattice.sage")
"""

from sage.all import *
import sys


def coppersmith_stereotyped(n, e, ct, known_prefix=b"", known_suffix=b"", max_unknown=100):
    """
    Coppersmith stereotyped message attack.
    Recovers plaintext when prefix and/or suffix of the message are known.

    Args:
        n: RSA modulus
        e: RSA public exponent
        ct: ciphertext (integer)
        known_prefix: known bytes at the start of the message
        known_suffix: known bytes at the end of the message
        max_unknown: maximum number of unknown bytes to try

    Returns:
        bytes: recovered plaintext, or None if not found
    """
    ZmodN = Zmod(n)
    prefix_int = int.from_bytes(known_prefix, 'big') if known_prefix else 0
    suffix_int = int.from_bytes(known_suffix, 'big') if known_suffix else 0
    suffix_len = len(known_suffix)

    for unknown_len in range(1, max_unknown + 1):
        # m = prefix || unknown || suffix
        # m = prefix_int * 256^(unknown_len + suffix_len) + x * 256^suffix_len + suffix_int
        P = PolynomialRing(ZmodN, 'x')
        x = P.gen()

        shift_suffix = Integer(256) ** suffix_len
        shift_total = Integer(256) ** (unknown_len + suffix_len)

        m_expr = prefix_int * shift_total + x * shift_suffix + suffix_int
        f = m_expr ** e - ct
        f = f.monic()

        X = Integer(256) ** unknown_len
        try:
            roots = f.small_roots(X=X, beta=1, epsilon=RR(1/30))
        except Exception:
            continue

        for root in roots:
            root = int(root)
            if root < 0:
                continue
            m_int = prefix_int * int(shift_total) + root * int(shift_suffix) + suffix_int
            # Verify: m^e == ct mod n
            if pow(m_int, e, n) == ct % n:
                byte_len = (m_int.bit_length() + 7) // 8
                try:
                    return m_int.to_bytes(byte_len, 'big')
                except OverflowError:
                    return int(m_int).to_bytes(byte_len, 'big')

    return None


def coppersmith_partial_p(n, p_high, unknown_bits):
    """
    Factor n given the high bits of p using Coppersmith's method.

    Args:
        n: RSA modulus (n = p * q)
        p_high: known high bits of p (shifted left by unknown_bits)
        unknown_bits: number of unknown low bits of p

    Returns:
        tuple: (p, q) or None if not found
    """
    ZmodN = Zmod(n)
    P = PolynomialRing(ZmodN, 'x')
    x = P.gen()

    f = p_high + x
    f = f.monic()

    X = Integer(2) ** unknown_bits
    try:
        roots = f.small_roots(X=X, beta=0.5)
    except Exception:
        return None

    for root in roots:
        p_candidate = int(p_high) + int(root)
        if p_candidate <= 1:
            continue
        if n % p_candidate == 0:
            q = n // p_candidate
            return (p_candidate, q)

    return None


def hnp_attack(t_values, a_values, q, bound):
    """
    Hidden Number Problem attack using Kannan embedding / LLL.
    Given t_i, a_i such that |t_i * secret - a_i|_q <= bound,
    recover the secret.

    Args:
        t_values: list of t_i values (multipliers)
        a_values: list of a_i values (known parts / MSBs)
        q: modulus
        bound: upper bound on the unknown part (e.g., 2^(leak_bits))

    Returns:
        int: recovered secret, or None
    """
    n = len(t_values)
    assert len(a_values) == n, "t_values and a_values must have the same length"

    # Build (n+2) x (n+2) Kannan embedding matrix
    # Columns: e_1, ..., e_n, secret, 1
    # Row i (0..n-1): q in position i (for mod q reduction)
    # Row n: t_values, then B/q scaling, then 0
    # Row n+1: a_values, then 0, then bound

    B = matrix(ZZ, n + 2, n + 2)

    # First n rows: q * I_n on the left, zeros elsewhere
    for i in range(n):
        B[i, i] = q

    # Row n: t_i values, then bound, then 0
    for i in range(n):
        B[n, i] = int(t_values[i])
    B[n, n] = bound
    B[n, n + 1] = 0

    # Row n+1: a_i values, then 0, then bound
    for i in range(n):
        B[n + 1, i] = int(a_values[i])
    B[n + 1, n] = 0
    B[n + 1, n + 1] = bound

    # LLL reduction
    L = B.LLL()

    # Search for the secret in reduced rows
    for row in L:
        # The secret appears as row[n] / bound (from Kannan embedding)
        if row[n] != 0 and row[n] % bound == 0:
            secret_candidate = int(row[n]) // int(bound)
            secret_candidate = secret_candidate % q
            if secret_candidate < 0:
                secret_candidate += q

            # Verify: check that t_i * secret - a_i is small mod q for all i
            valid = True
            for i in range(n):
                diff = (int(t_values[i]) * secret_candidate - int(a_values[i])) % q
                if diff > q // 2:
                    diff = q - diff
                if diff > int(bound):
                    valid = False
                    break
            if valid:
                return secret_candidate

    # Fallback: try all rows more aggressively
    for row in L:
        for j in range(n + 2):
            if row[j] == 0:
                continue
            # Try interpreting each non-zero entry as a potential secret
            candidate = int(row[j]) % q
            if candidate == 0:
                continue
            valid = True
            for i in range(min(3, n)):  # Quick check on first few
                diff = (int(t_values[i]) * candidate - int(a_values[i])) % q
                if diff > q // 2:
                    diff = q - diff
                if diff > int(bound):
                    valid = False
                    break
            if valid:
                # Full verification
                all_valid = True
                for i in range(n):
                    diff = (int(t_values[i]) * candidate - int(a_values[i])) % q
                    if diff > q // 2:
                        diff = q - diff
                    if diff > int(bound):
                        all_valid = False
                        break
                if all_valid:
                    return candidate

    return None


def knapsack_lll(weights, target):
    """
    Solve a subset-sum / knapsack problem using CJLOSS lattice reduction.

    Args:
        weights: list of integer weights
        target: target sum

    Returns:
        list: binary solution vector (0/1 for each weight), or None
    """
    n = len(weights)
    N = Integer(ceil(sqrt(n) / 2))

    # Build (n+1) x (n+1) CJLOSS lattice
    # Rows 0..n-1: identity matrix scaled by 2, plus weight in last column
    # Row n: zeros except last column = target (negative for subtraction)
    B = matrix(ZZ, n + 1, n + 1)

    for i in range(n):
        B[i, i] = 2
        B[i, n] = N * int(weights[i])

    B[n, n] = N * int(target)
    # Set the last row's diagonal-ish entries to 1 for offset
    for i in range(n):
        B[n, i] = 1

    L = B.LLL()

    for row in L:
        # In CJLOSS, solution vector entries are +1 (selected) or -1 (not selected)
        # After offset: original x_i = (row[i] + 1) / 2
        solution = []
        valid = True
        for i in range(n):
            val = int(row[i])
            if val == 1:
                solution.append(1)
            elif val == -1:
                solution.append(0)
            else:
                valid = False
                break

        if not valid:
            continue

        # Verify
        if sum(s * int(w) for s, w in zip(solution, weights)) == int(target):
            return solution

    # Alternative: try without offset encoding
    B2 = matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        B2[i, i] = 1
        B2[i, n] = int(weights[i])
    B2[n, n] = -int(target)

    L2 = B2.LLL()

    for row in L2:
        # Check if first n entries are binary and last entry is 0
        if row[n] != 0:
            continue
        solution = []
        valid = True
        for i in range(n):
            val = int(row[i])
            if val in (0, 1):
                solution.append(val)
            else:
                valid = False
                break
        if valid and sum(s * int(w) for s, w in zip(solution, weights)) == int(target):
            return solution

    return None


def coppersmith_dp(n, e, dp_partial, unknown_bits):
    """
    RSA dp (d mod p-1) partial knowledge attack.
    Given partial knowledge of dp, recover p and q.

    Args:
        n: RSA modulus
        e: public exponent
        dp_partial: known high bits of dp (or full dp with unknown low bits)
        unknown_bits: number of unknown bits in dp

    Returns:
        tuple: (p, q) or None
    """
    # dp = d mod (p-1), so e*dp = 1 mod (p-1)
    # => e*dp = 1 + k*(p-1) for some k in [1, e-1]
    # => p = (e*dp - 1 + k) / k = (e*dp - 1)/k + 1

    for k in range(1, int(e)):
        # If dp is fully known (unknown_bits == 0), direct computation
        if unknown_bits == 0:
            numerator = int(e) * int(dp_partial) - 1 + int(k)
            if numerator % int(k) != 0:
                continue
            p_candidate = numerator // int(k)
            if p_candidate > 1 and int(n) % p_candidate == 0:
                q = int(n) // p_candidate
                return (p_candidate, q)
        else:
            # dp = dp_partial_high * 2^unknown_bits + x, where 0 <= x < 2^unknown_bits
            # e * (dp_partial * 2^ub + x) ≡ 1 + k*(p-1)  ... complex
            # Instead: e*dp ≡ 1 (mod p-1) => e*dp - 1 ≡ 0 (mod p-1) => p | (e*dp - 1 + k)
            # With partial dp: p | (e*(dp_partial*2^ub + x) - 1 + k)
            # => f(x) = e*(dp_partial*2^ub + x) - 1 + k ≡ 0 (mod p)

            shift = Integer(2) ** unknown_bits
            base = int(e) * int(dp_partial) * int(shift) - 1 + int(k)

            # f(x) = e*x + base  mod p, and p | n
            ZmodN = Zmod(n)
            P = PolynomialRing(ZmodN, 'x')
            x = P.gen()

            f = int(e) * x + base
            f = f.monic()

            X = Integer(2) ** unknown_bits
            try:
                roots = f.small_roots(X=X, beta=0.5)
            except Exception:
                continue

            for root in roots:
                dp_full = int(dp_partial) * int(shift) + int(root)
                # Recover p from dp_full
                p_candidate_num = int(e) * dp_full - 1 + int(k)
                if p_candidate_num % int(k) != 0:
                    continue
                p_candidate = p_candidate_num // int(k)
                if p_candidate > 1 and int(n) % p_candidate == 0:
                    q = int(n) // p_candidate
                    return (p_candidate, q)

    return None


# === USAGE EXAMPLE ===
# Uncomment and modify for your challenge.

# --- Coppersmith Stereotyped Message ---
# n = 0x...
# e = 3
# ct = 0x...
# known_prefix = b"flag{"
# known_suffix = b"}"
# pt = coppersmith_stereotyped(n, e, ct, known_prefix, known_suffix, max_unknown=50)
# if pt:
#     print(f"[+] Plaintext: {pt}")

# --- Coppersmith Partial p ---
# n = p * q  (known)
# p_high = p >> 200 << 200  # known high bits, shifted back
# result = coppersmith_partial_p(n, p_high, unknown_bits=200)
# if result:
#     p, q = result
#     print(f"[+] p = {p}")
#     print(f"[+] q = {q}")

# --- HNP Attack (e.g., ECDSA nonce leak) ---
# # Given signatures (r_i, s_i) with top bits of nonce k_i known
# t_values = [int(inverse_mod(s_i, q) * r_i) for s_i, r_i in sigs]
# a_values = [int(inverse_mod(s_i, q) * h_i - k_i_high) for s_i, h_i, k_i_high in data]
# secret = hnp_attack(t_values, a_values, q, bound=2^leak_bits)
# if secret:
#     print(f"[+] Secret key: {secret}")

# --- Knapsack / Subset Sum ---
# weights = [283, 491, 733, ...]
# target = 1337
# sol = knapsack_lll(weights, target)
# if sol:
#     print(f"[+] Solution: {sol}")
#     print(f"[+] Selected: {[w for w, s in zip(weights, sol) if s]}")

# --- Coppersmith dp Leak ---
# n = 0x...
# e = 65537
# dp_partial = 0x...  # leaked dp value (or high bits)
# result = coppersmith_dp(n, e, dp_partial, unknown_bits=0)  # 0 if dp fully known
# if result:
#     p, q = result
#     d = inverse_mod(e, (p-1)*(q-1))
#     pt = pow(ct, d, n)
#     print(f"[+] Decrypted: {int(pt).to_bytes(256, 'big').strip(b'\\x00')}")

if __name__ == "__main__":
    print("[*] crypto_lattice.sage loaded successfully.")
    print("[*] Available functions:")
    print("    - coppersmith_stereotyped(n, e, ct, known_prefix, known_suffix, max_unknown)")
    print("    - coppersmith_partial_p(n, p_high, unknown_bits)")
    print("    - hnp_attack(t_values, a_values, q, bound)")
    print("    - knapsack_lll(weights, target)")
    print("    - coppersmith_dp(n, e, dp_partial, unknown_bits)")
    print("[*] Use: load('templates/crypto_lattice.sage') in your solve script.")
