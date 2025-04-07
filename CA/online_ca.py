import json
import socket

from dsa import dsa_verification
from utils import load_private_key


HOST = "127.0.0.1"
TCP_PORT = 2025

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

tcp.bind((HOST, TCP_PORT))

tcp.listen()

conn, _ = tcp.accept()


def verify_cert(m, r, s, filename='CA/ca_private_key_cert_001.pem'):
    private_key = load_private_key(filename)
    pv_nums = private_key.private_numbers()
    pb_nums = pv_nums.public_numbers

    return dsa_verification(m, r, s, pb_nums.y, pb_nums.parameter_numbers.p, pb_nums.parameter_numbers.q, pb_nums.parameter_numbers.g)


try:
    data = conn.recv(2048)
    cert = json.loads(data.decode('utf-8'))
    cert = cert['certificate']
    result = verify_cert(cert['public_key'],
                         cert['signature']['r'], cert['signature']['s'])

    if result:
        conn.sendall('True'.encode('utf-8'))
    else:
        conn.sendall('False'.encode('utf-8'))

except Exception as e:
    print(e)

conn.close()
