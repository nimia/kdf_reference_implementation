#! /usr/bin/env python3.6

import hashlib
import hmac

import binascii

EXPANSION_FACTOR_K = 3
PREFIX = b'KDF'
DERIVED_CRS = b'KDF_DERIVE'

def split_to_blocks(key, block_size):
    return [key[i:][:block_size] for i in range(0, len(key), block_size)]

class HashFunction:
    def __init__(self, hash_name):
        self.hash_name = hash_name
        self.hash_block_size = hashlib.new(hash_name).block_size

    def __call__(self, message):
        h = hashlib.new(self.hash_name)
        h.update(message)
        return h.digest()

    def hmac(self, key, message):
        return hmac.HMAC(key, message, self.hash_name).digest()

    def Hi(self, i, message):
        assert i <= 9
        block_num_as_char = bytes(str(i), 'ascii')
        assert len(block_num_as_char) == 1
        Ki = PREFIX + (block_num_as_char * (self.hash_block_size - len(PREFIX)))
        h = hashlib.new(self.hash_name)
        h.update(Ki)
        h.update(message)
        return h.digest()

def one_way_injective_function(k, x, hash_function):
    res = b''
    for i in range(k):
        res += hash_function.Hi(i, x)
    return res

def expand(key, hash_function):
    res = b''
    message_block_size = hash_function.hash_block_size
    key_split = split_to_blocks(key, block_size=message_block_size)
    for j in range(len(key_split)):
        for i in range(EXPANSION_FACTOR_K):
            res += hash_function.Hi(i, key_split[j])
    return res

def xor_bytes(bytes1, bytes2):
    if type(bytes1) != bytes:
        # Ugly hack to accommodate the recorder class for the tests.
        return bytes1 ^ bytes2
    assert len(bytes1) == len(bytes2)
    return bytes([bytes1[i] ^ bytes2[i] for i in range(len(bytes1))])

def combine_keys(k1, k2, hash_name, salt=b''):
    H = HashFunction(hash_name)
    k1_derived = H.hmac(k1, b'1' + DERIVED_CRS + salt)
    k2_derived = H.hmac(k2, b'2' + DERIVED_CRS + salt)
    k1_expanded = expand(k1, H)
    k2_expanded = expand(k2, H)
    return H(xor_bytes(H.hmac(k1_derived, b'1' + k2_expanded),
                       H.hmac(k2_derived, b'2' + k1_expanded)))

#test vectors
assert combine_keys(b'k1', b'a'*3 + b'b'*4 + b'c'*5, 'sha256', b'salt') == \
       b'\x1b"A\xd8&:\x10:w\x023\xfa%8\xc3\x98\xa7x \xaf\x02\x87\xc1]\xa8\xee\xf3 \xafd2\xa4'

k1 = bytearray.fromhex('4861b701f579fb629a4719b7411ed541cdbb71aa9df3ce567856441c738372d7')
k2 = bytearray.fromhex('a396e23f94a115207927659908c2f577472a8c226f0e3dd3ca4b0493cba5a0a9')
combined = combine_keys(k1, k2, 'sha256')
assert combined == bytearray.fromhex('f97aa8e39f9f8431a1289834f95d3dcd1251fb3af5dc4acc43a6a3cf2c1d62c9')
