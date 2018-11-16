from binascii import hexlify, unhexlify
from Crypto.Hash import SHA512
import hashlib

def hash_function(msg):
    hash_output = (hashlib.sha512(hex(msg).encode())).hexdigest()
    #hash_output = SHA512.new(msg.encode()).hexdigest()
    return hash_output


print(hash_function(21))
print(hash_function(22))