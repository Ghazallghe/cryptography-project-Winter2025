import random
from hashlib import sha256

from utils import is_prime


def dsa_prime_generation():
    while True:
        q = random.getrandbits(160) | (1 << 159)
        while not is_prime(q, 10):
            q = random.getrandbits(160) | (1 << 159)

        for _ in range(4096):
            m = random.getrandbits(1024) | (1 << 1023)
            m_r = m % (2 * q)
            p = m - m_r + 1
            if is_prime(p, 1):
                return p, q


def generator(p: int, q: int):
    h = random.randrange(2, p - 1)
    return pow(h, (p - 1) // q, p)


def dsa_keys():
    p, q = dsa_prime_generation()
    x = random.randrange(2, q)
    g = generator(p, q)
    y = pow(g, x, p)

    return y, p, q, g, x


def dsa_signature(m: str, x: int, p: int, q: int, g: int):
    m_hash = int(sha256(m.encode('utf-8')).hexdigest(), 16)
    k = random.randrange(2, q)
    r = pow(g, k, p) % q
    s = (pow(k, -1, q) * (m_hash + x * r)) % q
    return r, s


def dsa_verification(m: str, r: int, s: int, y: int, p: int, q: int, g: int):
    if not (0 < r < q and 0 < s < q):
        return False

    m_hash = int(sha256(m.encode('utf-8')).hexdigest(), 16)
    w = pow(s, -1, q)
    u1 = (m_hash * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    if v == r:
        return True

    return False
