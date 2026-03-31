#!/usr/bin/env python3
"""Schnorsa solver: phi leaked -> factor n -> DLP mod p,q -> recover x"""
import os, sys
from pwn import *
from Crypto.Util.number import GCD
import gmpy2

HOST = os.getenv("HOST", "host8.dreamhack.games")
PORT = int(os.getenv("PORT", "17350"))

def factor_from_phi(n, phi):
    """Factor n given phi: p+q = n-phi+1, p*q = n"""
    s = n - phi + 1  # p + q
    # p and q are roots of x^2 - s*x + n = 0
    disc = gmpy2.isqrt(s*s - 4*n)
    p = (s + disc) // 2
    q = (s - disc) // 2
    assert p * q == n
    return int(p), int(q)

def discrete_log_mod_prime(t, g, p):
    """Compute k such that g^k = t mod p using Pohlig-Hellman via sympy/sage"""
    # Try using sympy first
    from sympy.ntheory.residues import discrete_log as sympy_dlog
    try:
        k = sympy_dlog(p, t % p, g % p)
        return k
    except Exception as e:
        print(f"[!] sympy DLP failed: {e}")
        return None

def solve():
    io = remote(HOST, PORT)
    
    # Receive pubkey
    line = io.recvline().decode().strip()
    print(f"[*] {line}")
    # Parse: Pubkey: (e, phi, n, y)
    pubkey_str = line.split("Pubkey: ")[1]
    e, phi, n, y = eval(pubkey_str)
    nb = 1024
    
    print(f"[*] e = {e}")
    print(f"[*] n bits = {n.bit_length()}")
    print(f"[*] phi bits = {phi.bit_length()}")
    
    # Step 1: Factor n from phi
    p, q = factor_from_phi(n, phi)
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    
    # Step 2: Compute RSA private key
    d = int(gmpy2.invert(e, phi))
    print(f"[+] d computed")
    
    # Step 3: Get a signature
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"m: ", b"0")
    sig_line = io.recvline().decode().strip()
    print(f"[*] {sig_line}")
    r, s = eval(sig_line.split("Sig: ")[1])
    msg = 0
    
    # Step 4: Recover t = g^k mod n from r
    # r = (t << nb | msg)^e mod n => r^d mod n = t << nb | msg
    t_msg = pow(r, d, n)
    t = t_msg >> nb  # upper bits = t, lower nb bits = msg
    recovered_msg = t_msg & ((1 << nb) - 1)
    print(f"[*] recovered msg = {recovered_msg} (expected {msg})")
    print(f"[*] t = g^k mod n, t bits = {t.bit_length()}")
    
    # Step 5: Solve DLP mod p and mod q
    g = 2
    
    # Try mod p first
    print(f"[*] Attempting DLP mod p ({p.bit_length()} bits)...")
    tp = t % p
    gp = g % p
    
    # Check if order of g mod p divides p-1
    # Factor p-1 to check smoothness
    print(f"[*] Factoring p-1...")
    
    # Use sage-helper MCP for DLP if available, otherwise sympy
    k_p = discrete_log_mod_prime(t, g, p)
    if k_p is not None:
        print(f"[+] k mod ord_p(g) = {k_p}")
    else:
        print(f"[-] DLP mod p failed, trying alternate approach")
        # Alternate: since we know phi, try k = s - x*r mod phi
        # But we don't know x... that's circular
        # Try: use 2 signatures
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"m: ", b"1")
        sig_line2 = io.recvline().decode().strip()
        r2, s2 = eval(sig_line2.split("Sig: ")[1])
        
        # s1 = k1 + x*r1 mod phi
        # s2 = k2 + x*r2 mod phi
        # s1*r2 - s2*r1 = k1*r2 - k2*r1 mod phi
        # We need nonce relationship...
        print("[-] Need nonce analysis, falling back to nonce generator exploitation")
        io.close()
        return
    
    print(f"[*] Attempting DLP mod q ({q.bit_length()} bits)...")
    k_q = discrete_log_mod_prime(t, g, q)
    if k_q is not None:
        print(f"[+] k mod ord_q(g) = {k_q}")
    else:
        print(f"[-] DLP mod q failed")
        io.close()
        return
    
    # CRT to get k mod lcm(p-1, q-1)
    from sympy.ntheory.modular import crt
    order_p = p - 1
    order_q = q - 1
    k_candidates = crt([order_p, order_q], [k_p % order_p, k_q % order_q])
    if k_candidates is None:
        print("[-] CRT failed")
        io.close()
        return
    k = k_candidates[0]
    print(f"[+] k = {k}")
    
    # Step 6: Recover x
    # s = (k + x*r) mod phi => x = (s - k) * inverse(r, phi) mod phi
    r_inv = int(gmpy2.invert(r, phi))
    x = ((s - k) * r_inv) % phi
    print(f"[+] x = {x}")
    
    # Verify: g^x mod n should equal y
    if pow(g, x, n) == y:
        print(f"[+] VERIFIED: g^x mod n == y")
    else:
        print(f"[-] Verification failed, trying x mod phi variants...")
        # k might be the raw nonce value, not reduced mod phi
        # Try k directly
        for delta in range(0, 3):
            x_try = ((s - k - delta * phi) * r_inv) % phi
            if pow(g, x_try, n) == y:
                x = x_try
                print(f"[+] Found x with delta={delta}")
                break
    
    # Step 7: Submit x
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"x: ", str(x).encode())
    result = io.recvall(timeout=5).decode()
    print(result)
    
    io.close()

if __name__ == "__main__":
    solve()
