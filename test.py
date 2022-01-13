#! /usr/bin/env python3.6

import kdf_reference_implementation

assert kdf_reference_implementation.INITIAL_INPUT_BLOCKS == \
       [b'KDF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        b'KDF11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
        b'KDF22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222']

assert kdf_reference_implementation.split_to_blocks(''.join('0'*8 + '1'*8 + '2'*4), 8) == ['0'*8, '1'*8, '2'*4]

class Recorder:
    def __init__(self, data):
        self.data = data

    def __bytes__(self):
        return self.data
    
    def __xor__(self, other):
        return self.data + b' ^ ' + other.data

class IdentityHashFunction(kdf_reference_implementation.HashFunction):
    def __init__(self):
        pass
    
    def __call__(self, message):
        return message

    def hmac(self, key, message):
        return Recorder(b'HMAC(' + bytes(key) + b', ' + bytes(message) + b')')
    
    message_block_size = 8

assert kdf_reference_implementation.expand(b'a'*3 + b'b'*4 + b'c'*5, IdentityHashFunction()) == \
       b'KDF00000aaabbbbcKDF11111aaabbbbcKDF22222aaabbbbcKDF00000ccccKDF11111ccccKDF22222cccc'

assert kdf_reference_implementation.combine_keys(b'k1', b'a'*3 + b'b'*4 + b'c'*5, IdentityHashFunction(), b'salt') == \
       b'HMAC(HMAC(k1, 1KDF_DERIVEsalt), 1KDF00000aaabbbbcKDF11111aaabbbbcKDF22222aaabbbbcKDF00000ccccKDF11111ccccKDF22222cccc) ^ ' + \
       b'HMAC(HMAC(aaabbbbccccc, 2KDF_DERIVEsalt), 2KDF00000k1KDF11111k1KDF22222k1)'

sha256 = kdf_reference_implementation.sha256()
assert kdf_reference_implementation.combine_keys(b'k1', b'a'*3 + b'b'*4 + b'c'*5, sha256, b'salt') == \
       b'\x1b"A\xd8&:\x10:w\x023\xfa%8\xc3\x98\xa7x \xaf\x02\x87\xc1]\xa8\xee\xf3 \xafd2\xa4'
    
