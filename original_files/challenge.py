#! /usr/lib/python3

from boxes import sbox, pbox
from secrets import flag
from Crypto.Util.Padding import pad
import os
from binascii import hexlify

ROUNDS = 7
BLOCK_SIZE = 8


def encrypt(pt, key):

    pt = bytearray(pad(pt, BLOCK_SIZE))
    key = bytearray(key)

    blocks = [pt[i : i + BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]

    ct = bytearray()

    for block in blocks:
        for r in range(ROUNDS):

            for i in range(BLOCK_SIZE):
                block[i] = block[i] ^ key[i]

            for i in range(BLOCK_SIZE):
                block[i] = sbox[block[i]]

            pt_new = bytearray(BLOCK_SIZE)

            for i in range(BLOCK_SIZE):
                pt_new[i] = block[pbox[i]]

            block = pt_new
        ct += block
    return bytes(ct)


if __name__ == "__main__":

    k1 = os.urandom(BLOCK_SIZE >> 1)
    k2 = os.urandom(BLOCK_SIZE >> 1)

    key1 = k1 + k1
    key2 = k2 + k2

    ciphertext = encrypt(
        encrypt(b"I think I got it right this time. Maybe... " + flag, key1), key2
    )

    print(ciphertext.hex())
