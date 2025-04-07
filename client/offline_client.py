import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from my_rsa import rsa_keys


def save_private_key(pem_data: bytes, filename='client_private_key.pem'):
    path = os.path.join('client', filename)

    with open(path, 'wb') as f:
        f.write(pem_data)

    print('Private key save to', path)


def private_key_pem(n, e, d, p, q):
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    private_key = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e, n)
    ).private_key()

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem_data


def public_key_pem(n, e):
    public_key = rsa.RSAPublicNumbers(e, n).public_key()

    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_data


def csr_generate(public_key: bytes, dir_name='CSR', filename='csr.json'):
    csr_form = {
        'common_name': 'Client1',
        'organization': 'ExampleOrg',
        'organization_unit': 'IT',
        'country': 'US',
        'state': 'California',
        'locality': 'Los Angeles',
        'email': 'Client1@example.com',
        'public_key': public_key.decode('utf-8')
    }

    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    file_path = os.path.join(dir_name, filename)

    with open(file_path, 'w') as json_file:
        json.dump(csr_form, json_file)

    print(f'CSR form generated and stored successfully in {file_path}!!')


n, e, d, p, q = rsa_keys(bits=1024)
private_key = private_key_pem(n, e, d, p, q)
save_private_key(private_key)
public_key = public_key_pem(n, e)
csr_generate(public_key=public_key)
