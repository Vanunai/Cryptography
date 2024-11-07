from gmpy2 import gcd
from Crypto.Util.number import *
import tqdm 

p,q = 1009,3643
n = p*q
phi = (p-1)*(q-1)
ans = 0
for e in tqdm.trange(phi):
    if gcd(e, phi) == 1 and gcd(e-1, p-1) == 2 and gcd(e-1, q-1) == 2:
        ans += e
print(f"ans: {ans}")
    