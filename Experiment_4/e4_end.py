from gmpy2 import *
from Crypto.Util.number import *
import os

def load_data(base_file_path, filenames):
    m = []
    for filename in filenames:
        with open(os.path.join(base_file_path, filename), 'r') as fd:
            m.append(fd.read())
    n = [int(frame[0:256], 16) for frame in m]
    e = [int(frame[256:512], 16) for frame in m]
    c = [int(frame[512:768], 16) for frame in m]
    return n, e, c

def invmod(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = invmod(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

def CRT(items):
    N = 1
    for _, n in items:
        N *= n
    result = 0
    for a, n in items:
        m = N // n
        _, r, s = invmod(n, m)
        result += a * s * m
    return result % N, N

def small_exponent_attack(data, root_degree):
    x, _ = CRT(data)
    plaintext_root = gmpy2.iroot(gmpy2.mpz(x), root_degree)
    return long_to_bytes(plaintext_root[0])

def fermat_factorization(n):
    u0 = gmpy2.iroot(n, 2)[0] + 1
    i = 0
    while True:
        u = (u0 + i) ** 2 - n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            return u0 + i + v, u0 + i - v
        i += 1

def pollard_factorization(n):
    B = 2 ** 18
    a = 2
    for i in range(2, B + 1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
        if 1 < d < n:
            return d

def common_modulus_attack(e1, e2, c1, c2, n):
    gcd, s1, s2 = invmod(e1, e2)
    if s1 < 0:
        c1 = gmpy2.invert(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = gmpy2.invert(c2, n)
        s2 = -s2
    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    return long_to_bytes(m)

def main():
    base_file_path = "F:/大三上实验/crypto/Experiment_4/密码挑战赛赛题三/附件3-2"
    filenames = ['Frame' + str(i) for i in range(21)]
    n, e, c = load_data(base_file_path, filenames)

    # 小指数攻击
    print(small_exponent_attack([(c[3], n[3]), (c[8], n[8]), (c[12], n[12]), (c[16], n[16]), (c[20], n[20])], 5))

    # 费马分解法
    p, q = fermat_factorization(n[10])
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e[10], phi)
    m = pow(c[10], d, n[10])
    print(long_to_bytes(m))

    # Pollard分解法
    for idx in [2, 6, 19]:
        p = pollard_factorization(n[idx])
        q = n[idx] // p
        phi = (p - 1) * (q - 1)
        d = gmpy2.invert(e[idx], phi)
        m = pow(c[idx], d, n[idx])
        print(long_to_bytes(m))

    # 因数碰撞攻击
    p = gmpy2.gcd(n[1], n[18])
    for idx in [1, 18]:
        q = n[idx] // p
        phi = (p - 1) * (q - 1)
        d = gmpy2.invert(e[idx], phi)
        m = pow(c[idx], d, n[idx])
        print(long_to_bytes(m))

    # 公共模数攻击
    print(common_modulus_attack(e[0], e[4], c[0], c[4], n[0]))

if __name__ == "__main__":
    main()
