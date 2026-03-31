from Crypto.Util.number import long_to_bytes
from sympy import factorint

n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 3891158515405030211396309867177046660195995913985068178988858029936868358096672572274111514200511662

# Factor n (multi-prime RSA with small primes)
factors = factorint(n)
print(f"Factors: {factors}")

# Compute phi using all prime factors
phi = 1
for p, exp in factors.items():
    phi *= (p - 1) * (p ** (exp - 1))

d = pow(e, -1, phi)
m = pow(ct, d, n)
flag = long_to_bytes(m)
print(f"Flag: {flag.decode()}")
