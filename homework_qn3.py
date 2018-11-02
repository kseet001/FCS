import pyaes
from Crypto.Cipher import AES
from _datetime import datetime
from binascii import hexlify, unhexlify
import timeit
import time

''' Define the plaintext, IV and key '''
#plaintext = "\x00" * int(1.6 * 10 ** 8)    # 160 MB
plaintext = "\x00" * int(16) * 100000  # 16 bytes
key = "\x00" * 16  # 128 bits key
IV = "\x00" * 16  # 128 bits initialisation vector

''' PYAES implementation. '''
start = time.time()
aes = pyaes.AESModeOfOperationCBC(key.encode(), IV.encode())
plaintext_blocks = []
ciphertext = b''
for i in range(0, plaintext.__len__(), 1):
    if (i % 16 == 0):
        plaintext_blocks.append([])
    plaintext_blocks[int(i / 16)].append(plaintext[i])

for p in plaintext_blocks:
    ciphertext = ciphertext + aes.encrypt(p)
end = time.time()

trunc_cipher = hexlify(ciphertext)
trunc_cipher = trunc_cipher[trunc_cipher.__len__() - 32:]

print("\nResults from pyaes:")
#print("Ciphertext: %s" % (ciphertext))
print("Ciphertext (last 128 bits): %s" % (unhexlify(trunc_cipher)))
print("Time taken: %s seconds" % (end-start))

''' Pycrypto implementation. '''

start = time.time()
encryptor = AES.new(key, AES.MODE_CBC, IV)
ciphertext = encryptor.encrypt(plaintext)
end = time.time()

trunc_cipher = hexlify(ciphertext)
trunc_cipher = trunc_cipher[trunc_cipher.__len__() - 32:]

print("\nResults from pycrypto library:")
#print("Ciphertext: %s " % (ciphertext))
print("Ciphertext (last 128 bits): %s" % (unhexlify(trunc_cipher)))
print("Time taken: %s seconds" % (end-start))
