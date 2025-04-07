import json
import base64
import socket

from my_rsa import rsa_encryption
from cryptography.hazmat.primitives import serialization
from coco_cipher.coco_128 import encrypt_decrypt


HOST = "127.0.0.1"
TCP_PORT = 2020
TCP_CA_PORT = 2025

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

tcp.bind((HOST, TCP_PORT))

tcp.listen()

MASTER_KEY = b'=\x06\xfe0~7\x16}\xa3\xfd'


def generate_sym_key(key_length=16):
    key_stream = []
    key_len = len(MASTER_KEY)
    S, T = [], []
    for i in range(256):
        S.append(i)
        T.append(MASTER_KEY[i % key_len])

    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]

    i, j = 0, 0
    for _ in range(key_length):
        i = (i + 1) % 256
        j = (j + S[j]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        key_stream.append(S[t])

    return bytes(key_stream)


def encrypt_key(generated_key, public_key_pem):
    rsa_public_key = serialization.load_pem_public_key(public_key_pem.encode())
    rsa_public_numbers = rsa_public_key.public_numbers()
    return rsa_encryption(generated_key,
                          (rsa_public_numbers.n, rsa_public_numbers.e))


def verify_certificate(certificate):
    tcp_ca = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    tcp_ca.connect((HOST, TCP_CA_PORT))

    tcp_ca.sendall(json.dumps({'certificate': certificate}).encode('utf-8'))

    data = tcp_ca.recv(1024)
    return True if data.decode('utf-8') == 'True' else False


def decrypt_msg(cipher_text, shared_key, mode, nonce):
    return encrypt_decrypt(cipher_text, shared_key, mode, False, nonce)


def handle_client(client):
    try:
        while True:
            data = client.recv(2048)
            if not data:
                break

            data = json.loads(data.decode('utf-8'))

            if data['type'] == 'certificate':
                if verify_certificate(data["message"]):
                    global shared_key
                    global mode
                    mode = 'OFB'
                    shared_key = generate_sym_key()
                    key_enc = encrypt_key(
                        shared_key, data["message"]["public_key"])
                    client.sendall(json.dumps(
                        {'type': 'key', 'key': key_enc, 'mode': mode, 'message': 'Shared key is sent :D'}).encode())
                else:
                    client.sendall(json.dumps({"message", 'ERR'}).encode())
                    break
            elif data['type'] == 'cipher':
                print("Cipher Text base64", data['message'])
                print(f"\nIV: {data['nonce']}\n")
                cipher_text = base64.b64decode(data["message"])
                nonce = base64.b64decode(data["nonce"])
                msg = decrypt_msg(cipher_text, shared_key, mode, nonce)
                print(msg.decode())
                client.sendall(json.dumps(
                    {"type": "done", "message": "I received your secret message!!"}).encode())
                break

    except Exception as e:
        print(e)

    print(f'user disconnected')
    client.close()


c, addr = tcp.accept()
c.sendall(json.dumps(
    {"type": "certificate", "message": "Hi, would you please send your certification."}).encode('utf-8'))
handle_client(c)
