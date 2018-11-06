from Crypto.Cipher import AES
from binascii import hexlify

''' Define the plaintext, IV and key '''
#m1 = b"\xa0" * int(16)  # 16 bytes
key = b"\x00" * 16  # 128 bits key
IV = b"\x00" * 16  # 128 bits IV


def collision(message):
    m1 = message

    ''' To calculate CBC-MAC of message m, encrypt m in CBC mode with zero IV and obtain last 16bytes'''
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    ''' Obtain t1 '''
    t1 = encryptor.encrypt(m1)

    ''' Find c, where (t1 xor c) = m1 '''
    a = bytearray(t1)
    b = bytearray(m1)
    c = bytearray(len(a))
    for i in range(len(a)):
        c[i] = a[i] ^ b[i]
    m2 = m1 + c

    ''' Obtain t2 '''
    encryptor = AES.new(key, AES.MODE_CBC, IV)  # reinitiate encryptor
    t2 = encryptor.encrypt(m2)[16:]

    print("\nSame CBC-MAC is found for m1 and m2!")
    print("m1: \t\t\t%s" % (hexlify(m1)))
    print("CBC-MAC(m1): \t%s" % (hexlify(t1)))
    print("m2: \t\t\t%s" % (hexlify(m2)))
    print("CBC-MAC(m2): \t%s" % (hexlify(t2)))

def main():
    print("\nQuestion 2:")
    collision(b"\x00" * int(16))
    collision(b"\xa0" * int(16))
    collision(b"\xff" * int(8) + B"\x00" * int(8))

if __name__ == '__main__':
    main()