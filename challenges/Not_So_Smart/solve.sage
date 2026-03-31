#!/usr/bin/env sage
"""
Not So Smart - Smart's Attack on anomalous curve
Curve order = p => use p-adic lift to solve ECDLP
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib

# Parameters
p = 0x91f7989d5e019623425111dc87c6341898974a4286dd6080d23994ac7b39f0b7
a = 0x3043c0f99b2ff3e508255c08cb49f2df7e51b8faa5f181f95c164260a63fa96a
b = 0x244bfc977577b2e886524e4c58cb5e233bf6c32d265149640ca1cf11be4ad84d

F = GF(p)
E = EllipticCurve(F, [a, b])

g_x = 0x08f390922552640fd604f5dea148e1cdc11555535457a5474f6ef036c545203d
g_y = 0x05ad9e50b76b6af0e5d0fe5f3eae4f78d1b5a6e8f333cab237807d74334a76e7
G = E(g_x, g_y)

# From output.txt
Px = 18967137804592015321433852596446099783651635801031927546667662519327897949264
Py = 51878950646609279465160873411757881583198147506397321335972377510896867061403
P = E(Px, Py)

Qx = 45247794627663199855719600118312767438283240652545104631155981138796271885440
Qy = 41557770757629901825113762897064437585835652311804577964971081316706921316412
Q = E(Qx, Qy)

iv = bytes.fromhex("6c638f168c37a477dbc14f8a045548c8")
ct = bytes.fromhex("85130457085fc26b522c106a19cf2aa3a74297e48e39a1b5b230f04bb03da0a8")

# Verify anomalous
order = E.order()
print(f"Curve order: {order}")
print(f"p:           {p}")
print(f"Anomalous:   {order == p}")
assert order == p, "Curve is not anomalous!"

# Smart's Attack: lift to Qp and use p-adic logarithm
def smart_attack(P, Q, p):
    """
    Given P, Q on anomalous curve E/GF(p) with Q = k*P,
    recover k using Hensel lift to E/Qp.
    """
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0,0)*p for t in E.a_invariants()])

    P_Qp = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_l in P_Qp:
        if GF(p)(P_l.xy()[1]) == P.xy()[1]:
            break

    Q_Qp = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_l in Q_Qp:
        if GF(p)(Q_l.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p * P_l
    p_times_Q = p * Q_l

    # Extract p-adic logarithm: x/y of p*P and p*Q
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)

    k = ZZ(phi_Q) / ZZ(phi_P) % p
    return k

# Recover m from Q = m*G
print("Running Smart's attack to recover m from Q = m*G...")
m = smart_attack(G, Q, p)
print(f"m = {m}")

# Verify
assert m * G == Q, "Smart's attack failed: m*G != Q"
print("Verified: m*G == Q")

# Compute shared secret
shared_secret = (m * P).xy()[0]
print(f"shared_secret = {shared_secret}")

# Decrypt
key = hashlib.sha256(long_to_bytes(int(shared_secret))).digest()[:16]
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(f"Flag: {flag.decode()}")
