import numpy as np

from coco_cipher.s_box import s_box_op


def matrix_mul(z: bytearray):
    m = np.array([
        [0, 1, 1, 1, 1, 0, 0, 1],
        [1, 0, 1, 1, 1, 1, 0, 0],
        [1, 1, 0, 1, 0, 1, 1, 0],
        [1, 1, 1, 0, 0, 0, 1, 1],
        [0, 1, 1, 1, 1, 1, 1, 0],
        [1, 0, 1, 1, 0, 1, 1, 1],
        [1, 1, 0, 1, 1, 0, 1, 1],
        [1, 1, 1, 0, 1, 1, 0, 1],
    ])

    z2 = bytearray(8)
    for i in range(m.shape[0]):
        for j in range(m.shape[1]):
            if m[i][j] == 1:
                z2[7 - i] ^= z[7 - j]

    return z2


def round_func(x: bytearray, key: bytearray):
    key_rev = key[::-1]
    z = [a ^ b for a, b in zip(x, key_rev)]

    z[0] = s_box_op(z[0], 1)
    z[1] = s_box_op(z[1], 2)
    z[2] = s_box_op(z[2], 3)
    z[3] = s_box_op(z[3], 4)
    z[4] = s_box_op(z[4], 2)
    z[5] = s_box_op(z[5], 3)
    z[6] = s_box_op(z[6], 4)
    z[7] = s_box_op(z[7], 1)

    return matrix_mul(z)[::-1]
