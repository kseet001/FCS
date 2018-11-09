from binascii import hexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


key = b"\x11" * 16  # 128 bits key
print("Key is: ",hexlify(key))

IV = b"\x00" * 16  # 128 bits IV
print("IV is: ", hexlify(IV))
p = "SUTD-MSSD-51.505*Foundations-CS*SUTD-MSSD-51.505"
print("String is: ", p)
hexP = p.encode()

encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(IV),
        backend=default_backend()
    ).encryptor()


cipherText = encryptor.update(hexP) + encryptor.finalize()
print("Hash is: ", hexlify(cipherText))
