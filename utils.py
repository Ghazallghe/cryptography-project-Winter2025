import random
from cryptography.hazmat.primitives import serialization


def compute_u_r(p: int):
    u = 0
    r = p - 1
    while r % 2 == 0:
        r //= 2
        u += 1
    return u, r


def miller_rabin(p: int):
    u, r = compute_u_r(p)
    a = random.randint(2, p - 2)
    z = pow(a, r, p)
    if z == 1:
        return True
    for _ in range(u - 1):
        z = pow(z, 2, p)
        if z == (-1 % p):
            return True
    return False


def is_prime(p: int, s: int):
    if p == 1:
        return False
    if p == 2 or p == 3:
        return True
    if p % 2 == 0:
        return False

    for _ in range(s):
        if not miller_rabin(p):
            return False
    return True


def load_private_key(pem_file, password=None):
    with open(pem_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
        )
    return private_key


def load_public_key(pem_file):
    with open(pem_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key
