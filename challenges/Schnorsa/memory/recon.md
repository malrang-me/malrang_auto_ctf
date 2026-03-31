# Recon

## Challenge: Schnorsa (Crypto Lv6, Dreamhack)
- Remote: host8.dreamhack.games:17350
- 5 interactions allowed
- Goal: recover secret key x

## Protocol
- Schnorr signature over Z/nZ (RSA composite modulus)
- Pubkey: (e=0x10001, phi, n, y) -- phi is leaked!
- g = 2, y = g^x mod n
- Sign: k = get_nonce(), t = g^k mod n, r = (t<<nb | msg)^e mod n, s = (k + x*r) mod phi
- Option 2: submit x to get flag

## Key observations
1. phi is PUBLIC -> can factor n via quadratic: p+q = n-phi+1, p*q = n
2. d = e^(-1) mod phi -> RSA decrypt r to get t = g^k mod n
3. s = k + x*r mod phi -> x = (s-k) * inverse(r, phi) mod phi
4. Need k: DLP g^k = t mod p and mod q, then CRT
5. 512-bit p,q -> DLP might be feasible if p-1 has small factors (Pohlig-Hellman)
