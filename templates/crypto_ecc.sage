#!/usr/bin/env sage
"""ECC attack templates for CTF challenges.

Run via: wsl sage crypto_ecc.sage
Or import individual functions into your solve script.

Attacks:
- smart_attack: anomalous curves (#E == p)
- mov_attack: supersingular curves (small embedding degree)
- pohlig_hellman_ecc: smooth order curves
- singular_curve_attack: singular curves (discriminant = 0)
"""

from sage.all import *
import sys


def smart_attack(p, a, b, Gx, Gy, Qx, Qy):
    """Smart's attack on anomalous elliptic curves where #E(Fp) == p.

    Lifts points to Q_p (p-adic numbers) and computes the discrete log
    using the p-adic elliptic logarithm.

    Args:
        p, a, b: curve parameters for y^2 = x^3 + ax + b over GF(p)
        Gx, Gy: generator point coordinates
        Qx, Qy: target point coordinates (Q = d*G)

    Returns:
        d: discrete logarithm (integer)
    """
    E = EllipticCurve(GF(p), [a, b])
    G = E(Gx, Gy)
    Q = E(Qx, Qy)

    assert E.order() == p, f"Curve order {E.order()} != p={p}, not anomalous"

    # Lift curve to Qp
    Qp = pAdicField(p, 20)  # 20 digits of precision
    Ep = EllipticCurve(Qp, [Qp(a), Qp(b)])

    def _lift_point(P, E_Qp):
        """Lift a point from E(Fp) to E(Qp) with non-zero p-adic valuation."""
        x, y = ZZ(P.xy()[0]), ZZ(P.xy()[1])
        # Hensel lift
        for tx in range(p):
            xn = ZZ(x) + tx * p
            # Check if we can lift y
            rhs = xn^3 + ZZ(a)*xn + ZZ(b)
            try:
                yn = ZZ(Qp(rhs).sqrt())
                if yn % p == y % p:
                    return E_Qp(xn, yn)
                elif (-yn) % p == y % p:
                    return E_Qp(xn, -yn)
            except (ValueError, ArithmeticError):
                continue
        raise RuntimeError("Failed to lift point")

    G_lift = _lift_point(G, Ep)
    Q_lift = _lift_point(Q, Ep)

    # Compute p-adic logarithm: psi(P) = -x(P)/y(P) mod p^2
    # For the lifted points p*G_lift and p*Q_lift
    pG = p * G_lift
    pQ = p * Q_lift

    # Extract the p-adic logarithm
    x_pG, y_pG = pG.xy()
    x_pQ, y_pQ = pQ.xy()

    log_G = ZZ(-x_pG / y_pG) % p^2
    log_Q = ZZ(-x_pQ / y_pQ) % p^2

    # d = log_Q / log_G mod p
    d = ZZ(Mod(log_Q, p) / Mod(log_G, p))
    assert E(Gx, Gy) * d == E(Qx, Qy), "Verification failed"
    return d


def mov_attack(p, a, b, Gx, Gy, Qx, Qy, order):
    """MOV attack on supersingular curves with small embedding degree.

    Uses the Weil pairing to reduce ECDLP to DLP in GF(p^k)*.

    Args:
        p, a, b: curve parameters
        Gx, Gy: generator point
        Qx, Qy: target point (Q = d*G)
        order: order of G

    Returns:
        d: discrete logarithm
    """
    E = EllipticCurve(GF(p), [a, b])
    G = E(Gx, Gy)
    Q = E(Qx, Qy)

    # Find embedding degree k: smallest k such that order | p^k - 1
    k = 1
    for k in range(1, 50):
        if (p^k - 1) % order == 0:
            break
    else:
        raise RuntimeError("Embedding degree too large (>50), MOV attack infeasible")

    print(f"[*] Embedding degree k = {k}")

    # Extend to GF(p^k)
    Ek = EllipticCurve(GF(p^k, 'a'), [a, b])
    Gk = Ek(Gx, Gy)
    Qk = Ek(Qx, Qy)

    # Find a random point R of order `order` linearly independent from G
    while True:
        R = Ek.random_point()
        cofactor = Ek.order() // order
        R = cofactor * R
        if R.order() == order and R.weil_pairing(Gk, order) != 1:
            break

    # Weil pairing
    alpha = Gk.weil_pairing(R, order)  # e(G, R)
    beta = Qk.weil_pairing(R, order)   # e(Q, R) = e(dG, R) = e(G, R)^d

    print(f"[*] Computing DLP in GF(p^{k}) via Weil pairing...")
    d = beta.log(alpha)

    assert G * int(d) == Q, "Verification failed"
    return int(d)


def pohlig_hellman_ecc(p, a, b, Gx, Gy, Qx, Qy, order):
    """Pohlig-Hellman attack for smooth-order curves.

    Decomposes ECDLP into small subgroup DLPs and combines via CRT.

    Args:
        p, a, b: curve parameters
        Gx, Gy: generator point
        Qx, Qy: target point (Q = d*G)
        order: order of G (must be smooth)

    Returns:
        d: discrete logarithm
    """
    E = EllipticCurve(GF(p), [a, b])
    G = E(Gx, Gy)
    Q = E(Qx, Qy)

    factors = factor(order)
    print(f"[*] Order factorization: {factors}")

    residues = []
    moduli = []

    for (pi, ei) in factors:
        pe = pi^ei
        cofactor = order // pe

        Gi = cofactor * G  # subgroup generator of order pi^ei
        Qi = cofactor * Q  # projected target

        # Baby-step giant-step in small subgroup
        di = discrete_log(Qi, Gi, pe, operation='+')
        residues.append(di)
        moduli.append(pe)
        print(f"  d mod {pe} = {di}")

    d = CRT_list(residues, moduli)
    assert G * d == Q, "Verification failed"
    return int(d)


def singular_curve_attack(a, b, p, Gx, Gy, Qx, Qy):
    """Attack on singular elliptic curves (discriminant = 0).

    Maps points to the additive group (cusp) or multiplicative group (node),
    where DLP is trivial.

    Args:
        a, b, p: curve parameters for y^2 = x^3 + ax + b mod p
        Gx, Gy, Qx, Qy: point coordinates

    Returns:
        d: discrete logarithm
    """
    F = GF(p)

    disc = 4 * F(a)^3 + 27 * F(b)^2
    assert disc == 0, f"Curve is non-singular (disc={disc})"

    # Find the singular point
    # For y^2 = x^3 + ax + b, singular at 3x^2 + a = 0
    R = PolynomialRing(F, 'x')
    x = R.gen()
    roots = (3*x^2 + a).roots()

    if not roots:
        raise RuntimeError("Cannot find singular point over Fp")

    xs = roots[0][0]
    ys_sq = xs^3 + F(a)*xs + F(b)
    assert ys_sq == 0, "Singular point should have y=0"

    print(f"[*] Singular point: ({xs}, 0)")

    # Translate so singularity is at origin: x' = x - xs
    # New curve: y^2 = x'^3 + ... (expanded)
    # Check type: cusp (y^2 = x^3) or node (y^2 = x^2(x + c))
    a_new = 3*xs + F(a)  # should be 0 for singular
    b_new = 3*xs^2 + F(a)

    # After translation, y^2 = (x')^3 + 3*xs*(x')^2 + ...
    c = 3 * xs  # coefficient of (x')^2

    if c == 0:
        # Cusp: y^2 = x^3, map (x,y) -> y/x (additive group)
        print("[*] Cusp singularity, mapping to additive group")
        def to_additive(Px, Py):
            Px_t = F(Px) - xs
            if Px_t == 0:
                return F(0)
            return F(Py) / Px_t

        gval = to_additive(Gx, Gy)
        qval = to_additive(Qx, Qy)
        d = int(qval / gval)
    else:
        # Node: y^2 = x^2(x + c), map (x,y) -> (y + x*sqrt(c)) / (y - x*sqrt(c))
        print("[*] Node singularity, mapping to multiplicative group")
        sqrt_c = F(c).sqrt()

        def to_multiplicative(Px, Py):
            Px_t = F(Px) - xs
            Py_t = F(Py)
            return (Py_t + Px_t * sqrt_c) / (Py_t - Px_t * sqrt_c)

        gval = to_multiplicative(Gx, Gy)
        qval = to_multiplicative(Qx, Qy)
        d = int(discrete_log(qval, gval))

    print(f"[+] d = {d}")
    return d


# ============================================================
# Main: dispatch based on command-line or direct values
# ============================================================
if __name__ == '__main__':
    # Example: fill in your challenge values below and run
    # wsl sage crypto_ecc.sage

    print("ECC attack templates loaded.")
    print("Available: smart_attack, mov_attack, pohlig_hellman_ecc, singular_curve_attack")
    print()
    print("Example usage:")
    print("  d = smart_attack(p, a, b, Gx, Gy, Qx, Qy)")
    print("  d = pohlig_hellman_ecc(p, a, b, Gx, Gy, Qx, Qy, order)")

    # Uncomment and fill in for your challenge:
    # p = 0x...
    # a = ...
    # b = ...
    # Gx, Gy = ..., ...
    # Qx, Qy = ..., ...
    # order = ...  # if known
    #
    # # Pick the right attack:
    # d = smart_attack(p, a, b, Gx, Gy, Qx, Qy)
    # print(f"FLAG: d = {d}")
