from coco_cipher.s_box import s_box_op


def pre_key1(x: bytearray):
    z = bytearray(len(x))

    x0_4 = int.from_bytes(x[0:4], byteorder='big')
    x4_8 = int.from_bytes(x[4:8], byteorder='big')
    x8_12 = int.from_bytes(x[8:12], byteorder='big')
    x12_16 = int.from_bytes(x[12:16], byteorder='big')

    z[0:4] = (x0_4 ^ s_box_op(x[13], 5) ^ s_box_op(x[15], 6) ^ s_box_op(
        x[12], 7) ^ s_box_op(x[14], 8) ^ s_box_op(x[8], 7)).to_bytes(4, 'big')

    z[4:8] = (x8_12 ^ s_box_op(z[0], 5) ^ s_box_op(z[2], 6) ^ s_box_op(
        z[1], 7) ^ s_box_op(z[3], 8) ^ s_box_op(x[10], 8)).to_bytes(4, 'big')

    z[8:12] = (x12_16 ^ s_box_op(z[7], 5) ^ s_box_op(z[6], 6) ^ s_box_op(
        z[5], 7) ^ s_box_op(z[4], 8) ^ s_box_op(x[9], 5)).to_bytes(4, 'big')

    z[12:16] = (x4_8 ^ s_box_op(z[10], 5) ^ s_box_op(z[9], 6) ^ s_box_op(
        z[11], 7) ^ s_box_op(z[8], 8) ^ s_box_op(x[11], 6)).to_bytes(4, 'big')

    return z


def pre_key2(z: bytearray):
    x = bytearray(len(z))

    z0_4 = int.from_bytes(z[0:4], byteorder='big')
    z4_8 = int.from_bytes(z[4:8], byteorder='big')
    z8_12 = int.from_bytes(z[8:12], byteorder='big')
    z12_16 = int.from_bytes(z[12:16], byteorder='big')

    x[0:4] = (z8_12 ^ s_box_op(z[5], 5) ^ s_box_op(z[7], 6) ^ s_box_op(
        z[4], 7) ^ s_box_op(z[6], 8) ^ s_box_op(z[0], 7)).to_bytes(4, 'big')

    x[4:8] = (z0_4 ^ s_box_op(x[0], 5) ^ s_box_op(x[2], 6) ^ s_box_op(
        x[1], 7) ^ s_box_op(x[3], 8) ^ s_box_op(z[2], 8)).to_bytes(4, 'big')

    x[8:12] = (z4_8 ^ s_box_op(x[7], 5) ^ s_box_op(x[6], 6) ^ s_box_op(
        x[5], 7) ^ s_box_op(x[4], 8) ^ s_box_op(z[1], 5)).to_bytes(4, 'big')

    x[12:16] = (z12_16 ^ s_box_op(x[10], 5) ^ s_box_op(x[9], 6) ^ s_box_op(
        x[11], 7) ^ s_box_op(x[8], 8) ^ s_box_op(z[11], 6)).to_bytes(4, 'big')

    return x


def key_gen1(z: bytearray):
    k_a = (s_box_op(z[8], 5) ^ s_box_op(z[9], 6) ^ s_box_op(
        z[7], 7) ^ s_box_op(z[6], 8) ^ s_box_op(z[2], 5)).to_bytes(4, 'big')
    k_b = (s_box_op(z[10], 5) ^ s_box_op(z[11], 6) ^ s_box_op(
        z[5], 7) ^ s_box_op(z[4], 8) ^ s_box_op(z[6], 6)).to_bytes(4, 'big')

    k_c = (s_box_op(z[12], 5) ^ s_box_op(z[13], 6) ^ s_box_op(
        z[3], 7) ^ s_box_op(z[2], 8) ^ s_box_op(z[9], 7)).to_bytes(4, 'big')
    k_d = (s_box_op(z[14], 5) ^ s_box_op(z[15], 6) ^ s_box_op(
        z[1], 7) ^ s_box_op(z[0], 8) ^ s_box_op(z[13], 8)).to_bytes(4, 'big')

    return k_a + k_b, k_c + k_d


def key_gen2(x: bytearray):
    k_a = (s_box_op(x[3], 5) ^ s_box_op(x[2], 6) ^ s_box_op(
        x[12], 7) ^ s_box_op(x[13], 8) ^ s_box_op(x[8], 5)).to_bytes(4, 'big')
    k_b = (s_box_op(x[1], 5) ^ s_box_op(x[0], 6) ^ s_box_op(
        x[14], 7) ^ s_box_op(x[15], 8) ^ s_box_op(x[13], 6)).to_bytes(4, 'big')

    k_c = (s_box_op(x[7], 5) ^ s_box_op(x[6], 6) ^ s_box_op(
        x[8], 7) ^ s_box_op(x[9], 8) ^ s_box_op(x[3], 7)).to_bytes(4, 'big')
    k_d = (s_box_op(x[5], 5) ^ s_box_op(x[4], 6) ^ s_box_op(
        x[10], 7) ^ s_box_op(x[11], 8) ^ s_box_op(x[7], 8)).to_bytes(4, 'big')

    return k_a + k_b, k_c + k_d


def key_gen3(z: bytearray):
    k_a = (s_box_op(z[3], 5) ^ s_box_op(z[2], 6) ^ s_box_op(
        z[12], 7) ^ s_box_op(z[13], 8) ^ s_box_op(z[9], 5)).to_bytes(4, 'big')
    k_b = (s_box_op(z[1], 5) ^ s_box_op(z[0], 6) ^ s_box_op(
        z[14], 7) ^ s_box_op(z[15], 8) ^ s_box_op(z[12], 6)).to_bytes(4, 'big')

    k_c = (s_box_op(z[7], 5) ^ s_box_op(z[6], 6) ^ s_box_op(
        z[8], 7) ^ s_box_op(z[9], 8) ^ s_box_op(z[2], 7)).to_bytes(4, 'big')
    k_d = (s_box_op(z[5], 5) ^ s_box_op(z[4], 6) ^ s_box_op(
        z[10], 7) ^ s_box_op(z[11], 8) ^ s_box_op(z[6], 8)).to_bytes(4, 'big')

    return k_a + k_b, k_c + k_d


def key_gen4(x: bytearray):
    k_a = (s_box_op(x[8], 5) ^ s_box_op(x[9], 6) ^ s_box_op(
        x[7], 7) ^ s_box_op(x[6], 8) ^ s_box_op(x[3], 5)).to_bytes(4, 'big')
    k_b = (s_box_op(x[10], 5) ^ s_box_op(x[11], 6) ^ s_box_op(
        x[5], 7) ^ s_box_op(x[4], 8) ^ s_box_op(x[7], 6)).to_bytes(4, 'big')

    k_c = (s_box_op(x[12], 5) ^ s_box_op(x[13], 6) ^ s_box_op(
        x[3], 7) ^ s_box_op(x[2], 8) ^ s_box_op(x[8], 7)).to_bytes(4, 'big')
    k_d = (s_box_op(x[14], 5) ^ s_box_op(x[15], 6) ^ s_box_op(
        x[1], 7) ^ s_box_op(x[0], 8) ^ s_box_op(x[13], 8)).to_bytes(4, 'big')

    return k_a + k_b, k_c + k_d


def key_mng_round(x: bytearray, kg1, kg2):
    z = pre_key1(x)
    x = pre_key2(z)
    return x, kg1(z), kg2(x)


def key_generator(x: bytearray):
    keys = []
    key_gens = [key_gen1, key_gen2, key_gen3, key_gen4]

    for i in range(0, 8, 2):
        x, K1, K2 = key_mng_round(x, key_gens[i % 4], key_gens[(i + 1) % 4])
        keys.extend([K1[0], K1[1], K2[0], K2[1]])

    return keys
