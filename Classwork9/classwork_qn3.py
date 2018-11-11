import sys
from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


key = b"\x11" * 16  # 128 bits key
IV = b"\x00" * 16  # 128 bits IV
p = "SUTD-MSSD-51.505*Foundations-CS*SUTD-MSSD-51.505"

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')

def encrypt(key, plaintext):
    # Generate a random 96-bit IV.
    IV = b"\x00" * 16  # 128 bits IV

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(IV),
        backend=default_backend()
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (IV, ciphertext, encryptor.tag)

def decrypt(key, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    a = decryptor.update(ciphertext)
    print("Decrypted cipher: ", a)
    b = decryptor.finalize()
    return a + b

print("\na)")
print("Plaintext: ", p)
hexP = p.encode()
iv, ciphertext, tag = encrypt(key, hexP)
print("Tag is: ", hexlify(tag))
print("Ciphertext is : ", hexlify(ciphertext))

c1 = hexlify(ciphertext)[:32]
c2 = hexlify(ciphertext)[32:64]
c3 = hexlify(ciphertext)[64:]

print("\nc1: ", c1)
print("c2: ", c2)
print("c3: ", c3)

print("\nb)")
try:
    ciphertext = unhexlify(c3+c2+c1)
    print("Ciphertext: ", hexlify(ciphertext))
    plaintext_b = decrypt(key, IV, ciphertext, tag)
    print(plaintext_b)
except:
    print(sys.exc_info()[0])


print("\nc)")
try:
    ciphertext = unhexlify(c1+c2)
    print("Ciphertext: ", hexlify(ciphertext))
    plaintext_c = decrypt(key, IV, ciphertext, tag)
    print(plaintext_c)
except:
    print(sys.exc_info()[0])


print("\nd)")
try:
    ciphertext = int_to_bytes(int_from_bytes(ciphertext) + 1)
    print("Ciphertext: ", hexlify(ciphertext))
    plaintext_d = decrypt(key, IV, ciphertext, tag)
    print(plaintext_d)
except:
    print(sys.exc_info()[0])


