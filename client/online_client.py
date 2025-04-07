import socket
import threading
import json
import os
import base64
import random

from my_rsa import rsa_decryption
from utils import load_private_key
from coco_cipher.coco_128 import encrypt_decrypt

NONCE16 = b']-\x86\x92\xb5*7\xdf\xdd\xbf\x14H\x82{\xab\xda'
NONCE8 = b'R7-D\x92\xfe\xa7?'

HOST = "127.0.0.1"
TCP_PORT = 2020
MSG = "There is nothing more to be said or to be done tonight, so hand me over my violin and let us try to forget for half an hour the miserable weather and the still more miserable ways of our fellowmen."

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

tcp.connect((HOST, TCP_PORT))


def handle_receive():
    try:
        while True:
            msg = tcp.recv(1024).decode()
            if not msg:
                break
            msg = json.loads(msg)
            type = msg.get('type', '')
            print(f'\n{50*"="}\nServer: {msg["message"]}\n{50*"="}')
            if type == "key":
                global encrypted_shared_key, shared_key, mode
                encrypted_shared_key = msg["key"]
                mode = msg["mode"]
                shared_key = decrypt_shared_key(encrypted_shared_key)
                print(
                    f'\n{50*"*"}\nShared key is received and decrypted successfully!\n{50*"*"}')

            if type == "done":
                break
    except Exception as e:
        print(e)
        tcp.close()
    finally:
        print("Closing socket")
        tcp.close()
        os._exit(0)


def decrypt_shared_key(share_key, filename='client/client_private_key.pem'):
    private_key = load_private_key(filename)
    pv_nums = private_key.private_numbers()

    return rsa_decryption(int(share_key), (pv_nums.public_numbers.n, pv_nums.d))


def load_certificate(dir_name='CERT', filename='client_cert_001.json'):
    file_path = os.path.join(dir_name, filename)
    with open(file_path, 'r') as f:
        certificate = json.load(f)

    return certificate


def send_certificate():
    certificate = load_certificate()
    tcp.sendall(json.dumps(
        {
            'message': certificate,
            'type': 'certificate',
        }
    ).encode())


def encrypt_message(msg, key, mode):
    if key is None:
        print("Sorry this option isn't available now :(")
        return
    # IV
    if mode == 'CTR':
        nonce = NONCE8
    else:
        nonce = NONCE16

    nonce_b64 = base64.b64encode(nonce).decode()
    cipher_text = encrypt_decrypt(msg, key, mode, True, nonce)
    ct_b64 = base64.b64encode(cipher_text).decode()
    tcp.sendall(json.dumps(
        {'type': 'cipher', 'message': ct_b64, 'nonce': nonce_b64}).encode())


def home():
    print('Select an Option: ')
    print('1. Send Certificate')
    print('2. Print shared secret key')
    print('3. Send Encryption of a message')

    opt = input('\nEnter your option: ')

    if opt == '1':
        send_certificate()
    elif opt == '2':
        print(
            f'\n{50*"*"}\n{shared_key}\n{50*"*"}')
    elif opt == '3':
        encrypt_message(MSG, shared_key, mode)


threading.Thread(target=handle_receive).start()

while True:
    home()


tcp.close()
