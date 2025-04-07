import os
import json

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization


from dsa import dsa_keys, dsa_signature


def dsa_key_pem(y, p, q, g, x):
    public_numbers = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g))
    private_numbers = dsa.DSAPrivateNumbers(x, public_numbers)

    return public_numbers.public_key(), private_numbers.private_key()


def save_private_key(private_key, filename='ca_private_key_cert_001.pem'):
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    path = os.path.join('CA', filename)

    with open(path, 'wb') as f:
        f.write(pem_data)

    print(f"DSA Private key saved to {path}")


def save_public_key(public_key, filename='ca_public_key_cert_001.pem'):
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = os.path.join('CA', filename)

    with open(path, 'wb') as f:
        f.write(pem_data)

    print(f'DSA public key saved to {path}')


def sign_pub_key(x: int, p: int, q: int, g: int, csr_dir='CSR', csr_filename='csr.json'):
    path = os.path.join(csr_dir, csr_filename)

    with open(path, 'r') as file:
        csr_form = json.load(file)

    public_key = csr_form['public_key']
    return dsa_signature(public_key, x, p, q, g), public_key


def certification_generate(public_key, signature, dir_name='CERT', filename='client_cert_001.json'):
    r, s = signature
    cert_form = {
        'certificate_id': 'cert_001',
        'issued_to': 'client1',
        'organization': 'ExampleOrg',
        'issued_by': 'Me',
        'public_key': public_key,
        'signature': {
            'r': r,
            's': s
        },
        'validity_period': '2025-01-18 to 2025-11-26',
    }
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    file_path = os.path.join(dir_name, filename)

    with open(file_path, 'w') as json_file:
        json.dump(cert_form, json_file)

    print(f'Certification generated and stored successfully in {file_path}!!')


y, p, q, g, x = dsa_keys()
pub_key, prv_key = dsa_key_pem(y, p, q, g, x)
save_private_key(private_key=prv_key)
save_public_key(public_key=pub_key)
signature, rsa_pub_key = sign_pub_key(x, p, q, g)
certification_generate(public_key=rsa_pub_key, signature=signature)
