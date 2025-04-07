import random
import math

from utils import is_prime


def generate_prime(bits=512, s=5):
    num = random.getrandbits(bits) | (1 << (bits-1))
    while not is_prime(num, s):
        num = random.getrandbits(bits) | (1 << (bits-1))
    return num


def choose_e(phi_n: int):
    e = random.randrange(2, phi_n)
    while math.gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)
    return e


def rsa_keys(bits=1024):
    p = generate_prime(bits=bits)
    q = generate_prime(bits=bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = choose_e(phi_n=phi_n)
    d = pow(e, -1, phi_n)

    return n, e, d, p, q


def rsa_encryption(m, public_key):
    n, e = public_key
    if isinstance(m, str):
        m = m.encode()
    m_int = int.from_bytes(m, byteorder='big')
    return pow(m_int, e, n)


def rsa_decryption(c: int, private_key):
    n, d = private_key
    decrypted_int = pow(c, d, n)
    decrypted_message = decrypted_int.to_bytes(
        (decrypted_int.bit_length() + 7) // 8, byteorder='big')
    return decrypted_message
