from gmpy2 import powmod
from Crypto.Util.number import *

e = 0x10001
p = getPrime(512)
q = getPrime(512)
N = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(e*d%phi)
m = b"Vanuna {have a n1ce day !}"
m = bytes_to_long(m)
c = powmod(m, e, N)
print(f"N: {N}")
print(f"e: {e}")
print(f"c: {c}")
print(f"m: {long_to_bytes(powmod(c, d, N))}")
assert m == powmod(c, d, N)
