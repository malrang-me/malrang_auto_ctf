#!/usr/bin/env python3
"""
Not So Smart - Smart's Attack on anomalous curve (pure Python)
Uses the standard p-adic lift approach for anomalous curves.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib
from math import gcd

# Parameters
p = 0x91f7989d5e019623425111dc87c6341898974a4286dd6080d23994ac7b39f0b7
a = 0x3043c0f99b2ff3e508255c08cb49f2df7e51b8faa5f181f95c164260a63fa96a
b = 0x244bfc977577b2e886524e4c58cb5e233bf6c32d265149640ca1cf11be4ad84d

# Generator
Gx = 0x08f390922552640fd604f5dea148e1cdc11555535457a5474f6ef036c545203d
Gy = 0x05ad9e50b76b6af0e5d0fe5f3eae4f78d1b5a6e8f333cab237807d74334a76e7

# From output.txt
Px = 18967137804592015321433852596446099783651635801031927546667662519327897949264
Py = 51878950646609279465160873411757881583198147506397321335972377510896867061403
Qx = 45247794627663199855719600118312767438283240652545104631155981138796271885440
Qy = 41557770757629901825113762897064437585835652311804577964971081316706921316412

iv = bytes.fromhex("6c638f168c37a477dbc14f8a045548c8")
ct = bytes.fromhex("85130457085fc26b522c106a19cf2aa3a74297e48e39a1b5b230f04bb03da0a8")


def ec_add_mod(P, Q, a, mod):
    """Elliptic curve addition mod n. Returns None for point at infinity."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 % mod == x2 % mod:
        if (y1 + y2) % mod == 0:
            return None
        denom = (2 * y1) % mod
        numer = (3 * x1 * x1 + a) % mod
    else:
        denom = (x2 - x1) % mod
        numer = (y2 - y1) % mod
    g = gcd(denom % mod, mod)
    if g > 1:
        return None  # point at infinity in this ring
    lam = numer * pow(denom, -1, mod) % mod
    x3 = (lam * lam - x1 - x2) % mod
    y3 = (lam * (x1 - x3) - y1) % mod
    return (x3, y3)


def ec_mul_mod(k, P, a, mod):
    """Scalar multiplication k*P mod n."""
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add_mod(R, Q, a, mod)
        Q = ec_add_mod(Q, Q, a, mod)
        k >>= 1
    return R


def hensel_lift(px, py, p, a, b):
    """
    Lift point (px, py) from E(F_p) to E(Z/p^2Z).
    Keep x the same, adjust y.
    """
    mod = p * p
    x = px
    # f(x) = x^3 + a*x + b
    fx = (x**3 + a*x + b) % mod
    y_sq = (py * py) % mod
    diff = (fx - y_sq) % mod
    assert diff % p == 0
    t = ((diff // p) * pow(2 * py, -1, p)) % p
    new_y = (py + t * p) % mod
    return (x % mod, new_y)


def padic_log(P_lift, p, a):
    """
    Compute the p-adic elliptic logarithm.
    For a point in the kernel of reduction (i.e., p * P_lift on E(Z/p^2)),
    compute -x/y mod p (after dividing out p from the formal group parameter).

    Returns the logarithm value mod p.
    """
    mod = p * p
    # Compute p * P_lift on E(Z/p^2Z)
    # Since the curve is anomalous, this should give a point in the formal group
    # i.e., a point that reduces to O mod p

    # We need to be more careful: instead of computing p*P and extracting -x/y,
    # we track when the computation "goes to infinity" mod p but not mod p^2.
    #
    # Alternative approach: use the formal group directly.
    # For anomalous curves, we can compute the discrete log using the
    # "division polynomial" approach or track denominators.

    # Let's use a different method: compute (p-1)*P_lift, then the last addition
    # (adding P_lift to get p*P_lift) will have a denominator divisible by p.
    # The ratio of numerator to denominator gives us the log.

    # Actually, let me try a cleaner approach using projective coordinates.
    pass


def smart_attack_projective(Gx, Gy, Qx, Qy, p, a, b):
    """
    Smart's attack using projective coordinates to properly handle p-adic lift.
    We work in projective coordinates [X:Y:Z] over Z/p^2Z.
    """
    mod = p * p

    # Lift points
    G_lift = hensel_lift(Gx, Gy, p, a, b)
    Q_lift = hensel_lift(Qx, Qy, p, a, b)

    # We need to compute p * G_lift and p * Q_lift in E(Z/p^2Z)
    # Using projective coordinates [X:Y:Z] to track the "infinity" properly

    def proj_add(P, Q):
        """Addition in projective coords [X:Y:Z] over Z/p^2Z."""
        if P is None: return Q
        if Q is None: return P
        X1, Y1, Z1 = P
        X2, Y2, Z2 = Q

        U1 = (Y2 * Z1) % mod
        U2 = (Y1 * Z2) % mod
        V1 = (X2 * Z1) % mod
        V2 = (X1 * Z2) % mod

        if V1 % mod == V2 % mod:
            if U1 % mod != U2 % mod:
                return None  # point at infinity
            # Doubling
            if Y1 % mod == 0:
                return None
            W = (a * Z1 * Z1 + 3 * X1 * X1) % mod
            S = (Y1 * Z1) % mod
            B = (X1 * Y1 * S) % mod
            H = (W * W - 8 * B) % mod
            X3 = (2 * H * S) % mod
            Y3 = (W * (4 * B - H) - 8 * Y1 * Y1 * S * S) % mod
            Z3 = (8 * S * S * S) % mod
            return (X3 % mod, Y3 % mod, Z3 % mod)

        U = (U1 - U2) % mod
        V = (V1 - V2) % mod
        V2_ = (V * V) % mod
        V3 = (V2_ * V) % mod
        V2U2 = (V2_ * X1 * Z2) % mod  # Actually need more standard formula

        # Use standard projective addition formulas
        # P1 = [X1:Y1:Z1], P2 = [X2:Y2:Z2]
        # u = Y2*Z1 - Y1*Z2
        # v = X2*Z1 - X1*Z2
        u = U
        v = V
        v2 = (v * v) % mod
        v3 = (v2 * v) % mod
        w = (u * u * Z1 * Z2 - v3 - 2 * v2 * X1 * Z2) % mod
        X3 = (v * w) % mod
        Y3 = (u * (v2 * X1 * Z2 - w) - v3 * Y1 * Z2) % mod
        Z3 = (v3 * Z1 * Z2) % mod
        return (X3 % mod, Y3 % mod, Z3 % mod)

    def proj_mul(k, P):
        R = None
        Q = P
        while k > 0:
            if k & 1:
                R = proj_add(R, Q)
            Q = proj_add(Q, Q)
            k >>= 1
        return R

    # Convert lifted points to projective
    G_proj = (G_lift[0], G_lift[1], 1)
    Q_proj = (Q_lift[0], Q_lift[1], 1)

    # Compute p * G_lift and p * Q_lift
    pG = proj_mul(p, G_proj)
    pQ = proj_mul(p, Q_proj)

    if pG is None or pQ is None:
        raise ValueError("Got point at infinity - try different lift")

    # For points in the kernel of reduction, Z is divisible by p
    # The p-adic log is: (X/Z) / (Y/Z) = X*Z / Y  ... actually
    # The formal group parameter is t = -X/Y (in projective: -X*Z/Y... hmm)
    # Actually for [X:Y:Z] with Z divisible by p:
    # affine x = X/Z, affine y = Y/Z
    # log = -x/y = -(X/Z)/(Y/Z) = -X/Y
    # But we want this mod p, after extracting the p factor

    # Actually the formal group parameter is t = -x/y for the affine point
    # For kernel points, x and y have poles, but t = -x/y is well-defined
    # In projective: t = -X/(Y) * Z/Z ... let me think again
    #
    # In projective [X:Y:Z], affine coords are (X/Z, Y/Z)
    # t = -(X/Z) / (Y/Z) = -X/Y
    # This should be = c*p mod p^2 for some c

    XG, YG, ZG = pG
    XQ, YQ, ZQ = pQ

    # Compute -X/Y mod p^2
    tG = (-XG * pow(YG, -1, mod)) % mod
    tQ = (-XQ * pow(YQ, -1, mod)) % mod

    # These should be divisible by p
    if tG % p != 0 or tQ % p != 0:
        # Try X*Z/Y or other formulation
        # Actually let's try the affine approach: x/y where x = X/Z, y = Y/Z
        # But Z might not be invertible mod p^2 if p | Z
        # In that case, use -X/Y directly
        print(f"tG mod p = {tG % p}, tQ mod p = {tQ % p}")
        # Try: log = X/Y (without the minus)
        tG = (XG * pow(YG, -1, mod)) % mod
        tQ = (XQ * pow(YQ, -1, mod)) % mod

    logG = tG // p
    logQ = tQ // p

    m = (logQ * pow(logG, -1, p)) % p
    return m


# Verify anomalous
print("Verifying curve is anomalous...")
result = ec_mul_mod(p, (Gx, Gy), a, p)
assert result is None, "Curve is NOT anomalous"
print("Confirmed: curve is anomalous (#E = p)")

# Run Smart's attack
print("\nRunning Smart's attack...")
m = smart_attack_projective(Gx, Gy, Qx, Qy, p, a, b)
print(f"m = {m}")

# Verify
mG = ec_mul_mod(m, (Gx, Gy), a, p)
if mG == (Qx, Qy):
    print("Verified: m*G == Q")
else:
    print(f"m*G = {mG}")
    print(f"Q   = ({Qx}, {Qy})")
    # Try p - m
    m2 = p - m
    mG2 = ec_mul_mod(m2, (Gx, Gy), a, p)
    if mG2 == (Qx, Qy):
        print(f"Using m = p - m = {m2}")
        m = m2
    else:
        print("ERROR: Smart's attack did not produce correct m")
        exit(1)

# Compute shared secret
shared_point = ec_mul_mod(m, (Px, Py), a, p)
shared_secret = shared_point[0]
print(f"\nshared_secret = {shared_secret}")

# Decrypt
key = hashlib.sha256(long_to_bytes(int(shared_secret))).digest()[:16]
try:
    flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    print(f"Flag: {flag.decode()}")
except Exception as e:
    print(f"Decryption failed: {e}")
    # Also try with n instead
    print("Trying to recover n from P = n*G...")
    n = smart_attack_projective(Gx, Gy, Px, Py, p, a, b)
    nG = ec_mul_mod(n, (Gx, Gy), a, p)
    if nG != (Px, Py):
        n = p - n
    shared_point2 = ec_mul_mod(n, (Qx, Qy), a, p)
    shared_secret2 = shared_point2[0]
    print(f"shared_secret (via n) = {shared_secret2}")
    key2 = hashlib.sha256(long_to_bytes(int(shared_secret2))).digest()[:16]
    flag = unpad(AES.new(key2, AES.MODE_CBC, iv).decrypt(ct), 16)
    print(f"Flag: {flag.decode()}")
