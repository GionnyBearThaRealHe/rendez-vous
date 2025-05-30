#! /usr/lib/python3

from boxes import sbox, pbox
#from secrets import flag
from Crypto.Util.Padding import pad
import os
from binascii import hexlify

# this is the original .py file provided by the challenge, slightly modified to be ran without encountering problems circa the absence of the flag and implementing a decryption function to be imported into other modules
ROUNDS = 7
BLOCK_SIZE = 8

def decrypt(ct, key):

    key = bytearray(key)

    blocks = [ct[i : i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    pt = bytearray()

    for block in blocks:
        for r in range(ROUNDS):
            pt_new = bytearray(BLOCK_SIZE)

            for i in range(BLOCK_SIZE):
                pt_new[pbox[i]] = block[i]

            block = pt_new

            for i in range(BLOCK_SIZE):
                block[i] = sbox.index(block[i])

            for i in range(BLOCK_SIZE):
                block[i] = block[i] ^ key[i]

        pt += block
    return bytes(pt)

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

    k1 = os.urandom(BLOCK_SIZE >> 1)#4
    k2 = os.urandom(BLOCK_SIZE >> 1)#4

    key1 = k1 + k1
    key2 = k2 + k2

    flag = 'flag{hehehe_this_is_a_placeholder}'
    ciphertext = encrypt(
        encrypt(b"I think I got it right this time. Maybe... "+flag , key1), key2
    )

    print(ciphertext.hex())
