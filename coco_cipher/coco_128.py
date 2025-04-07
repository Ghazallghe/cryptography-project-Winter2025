from coco_cipher.key_management import key_generator
from coco_cipher.round_function import round_func

BLOCK_SIZE = 128
N_ROUNDS = 16
NONCE16 = b']-\x86\x92\xb5*7\xdf\xdd\xbf\x14H\x82{\xab\xda'
NONCE8 = b'R7-D\x92\xfe\xa7?'


def coco_128(x: bytearray, key: bytearray, enc=True):
    sub_keys = key_generator(key)
    if not enc:
        sub_keys = sub_keys[::-1]

    n = len(x)
    left, right = x[:n // 2], x[n // 2:]
    for i in range(N_ROUNDS):
        round_res = round_func(right, sub_keys[i])
        left, right = right, bytearray(a ^ b for a, b in zip(round_res, left))

    return right + left


def process_input(inp: str, enc):
    inp_bytes = inp
    if enc:
        # message encode
        inp_bytes = inp.encode()
    l = len(inp_bytes)

    # message blocks
    blocks = [inp_bytes[i:i+BLOCK_SIZE // 8]
              for i in range(0, l, BLOCK_SIZE // 8)]

    # Add padding
    padding_size = (BLOCK_SIZE // 8) - len(blocks[-1])
    blocks[-1] += bytes([0] * padding_size)

    return blocks


def encrypt_decrypt(input: str, key, mode: str, enc: bool, nonce: bytearray):
    blocks = process_input(input, enc)
    if isinstance(key, str):
        key = key.encode()
    res = bytearray()

    if mode == 'ECB':
        res = bytearray().join(
            [coco_128(x=block, key=key, enc=enc) for block in blocks])

    if mode == 'OFB':
        next_block = nonce
        for block in blocks:
            next_block = coco_128(x=next_block, key=key)
            res += bytearray(a ^ b for a, b in zip(block, next_block))

    if mode == 'CTR':
        for counter, block in enumerate(blocks):
            iv = nonce + counter.to_bytes(8, 'big')
            tmp = coco_128(x=iv, key=key)
            res += bytearray(a ^ b for a, b in zip(block, tmp))

    if mode == 'CBC':
        next_nonce = nonce
        if enc:
            for block in blocks:
                inp = bytearray(a ^ b for a, b in zip(block, next_nonce))
                next_nonce = coco_128(x=inp, key=key, enc=enc)
                res += next_nonce
        else:
            for block in blocks:
                out = coco_128(x=block, key=key, enc=enc)
                res += bytearray(a ^ b for a, b in zip(out, next_nonce))
                next_nonce = block

    return res


# plaintext = 'Hi how are you? What are you doing?'
# key = 'abcdefghijklmnop'

# ct = encrypt_decrypt(input=plaintext, key=key, mode='ECB', enc=True)
# print('Cipher text(ECB)', ct.hex())
# print()
# print('Plaintext', encrypt_decrypt(input=ct, key=key, mode='ECB', enc=False))
# print('-'*50)

# ct = encrypt_decrypt(input=plaintext, key=key, mode='OFB', enc=True)
# print('Cipher text(OFB)', ct.hex())
# print()
# print('Plaintext', encrypt_decrypt(input=ct, key=key, mode='OFB', enc=False))
# print('-'*50)

# ct = encrypt_decrypt(input=plaintext, key=key,
#                      mode='CTR', enc=True, nonce=NONCE8)
# print('Cipher text(CTR)', ct.hex())
# print()
# print('Plaintext', encrypt_decrypt(
#     input=ct, key=key, mode='CTR', enc=False, nonce=NONCE8))
# print('-'*50)

# ct = encrypt_decrypt(input=plaintext, key=key, mode='CBC', enc=True)
# print('Cipher text(CBC)', ct.hex())
# print()
# print('Plaintext', encrypt_decrypt(input=ct, key=key, mode='CBC', enc=False))
