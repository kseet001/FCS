from Crypto.Cipher import AES
from binascii import hexlify

''' Define the plaintext, IV and key '''
m1 = "\xff" * int(16)  # 16 bytes
key = "\x00" * 16  # 128 bits key
IV = "\x00" * 16  # 128 bits IV

''' To calculate CBC-MAC of message m, encrypt m in CBC mode with zero IV and obtain last 16bytes'''
encryptor = AES.new(key.encode(), AES.MODE_CBC, IV.encode())

''' Obtain t1 '''
t1 = encryptor.encrypt(m1.encode())

''' Find c, where (t1 xor c) = m1 '''
a = bytearray(t1)
b = bytearray(m1.encode())
c = bytearray(len(a))
for i in range(len(a)):
    c[i] = a[i] ^ b[i]
m2 = m1.encode()+c     # This step still need to work on it

''' Test1 '''
encryptor = AES.new(key.encode(), AES.MODE_CBC, IV.encode()) # reinitiate encryptor
t2 = encryptor.encrypt(m2)[16:]

print("\nPlaintext 1: %s" %(hexlify(m1.encode())))
print("CBC-MAC, t1: %s" %(hexlify(t1)))
print("Plaintext 2: %s" %(hexlify(m2)))
print("CBC-MAC, t2: %s" %(hexlify(t2)))