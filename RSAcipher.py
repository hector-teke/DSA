import math
import random
from sympy import isprime

###################### OT -> Integer

def text_to_vector(OT):
    vector = []
    while len(OT) >= 5:
        vector.append(block_to_int(OT[-5:]))
        # print(OT[-5:], " \tnum: ", vector)
        OT = OT[0:-5]

    if len(OT) > 0:
        vector.append(block_to_int(OT))
        # print(OT, "  \tnum: ", vector)

    return vector[::-1]


def block_to_int(blk):
    bin_string = ""

    for c in blk:
        bin_string += int_to_bin(ord(c))

    return int(bin_string, 2)


# 8-bit codification of a given integer
def int_to_bin(n):
    bin_string = bin(n)[2:]
    return (8 - len(bin_string)) * '0' + bin_string


###################### Integer -> OT

def vector_to_text(vector):
    OT = ""
    for n in vector:
        OT += int_to_block(n)

    return OT


def int_to_block(num):
    blk = ""
    bin_string = bin(num)[2:]
    bin_string = (8 - (len(bin_string) % 8)) * '0' + bin_string

    for i in range(0, len(bin_string), 8):
        blk += chr(int(bin_string[i:i + 8], 2))
        # print(i, "\t", bin_string[i:i+8])

    return blk


###################### Encryption and decryption

def encryption(OT, e, n):
    #print(f'OT: {OT}')
    CT = []
    for blk in text_to_vector(OT):
        #print(f'Block: {blk} ({type(blk)}), Key: {e}, Module: {n}')
        CT.append(pow(blk, e, n))
    print(CT)
    return CT


def decryption(CT, d, n):
    OT = []
    for blk in CT:
        OT.append(pow(blk, d, n))

    return vector_to_text(OT)


###################### Keys generation

def generate_primes(bits):
    p1 = None
    p2 = None

    while p1 == p2:
        p1 = random.getrandbits(bits)
        p1 |= (1 << bits - 1) | 1
        while not isprime(p1):
            p1 += 2  # Avoid even numbers

        p2 = random.getrandbits(bits)
        p2 |= (1 << bits - 1) | 1
        while not isprime(p2):
            p2 += 2  # Avoid even numbers

    return p1, p2


def select_e(phi):
    while True:
        e = random.randint(2, phi - 1)      # 1 < e < phi
        if math.gcd(e, phi) == 1:  # GCD(e, phi) = 1
            break
    return e


def generate_keys(bits):
    p, q = generate_primes(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = select_e(phi)
    d = pow(e, -1, phi)

    return e, d, n      # Pub, Priv, Module