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
    a = b"\x00" * int(16)
    encryptor = AES.new(key,AES.MODE_CBC, IV)
    decryptor = AES.new(key,AES.MODE_CBC,IV)

    print("a : \t\t\t\t%s"%(hexlify(a)))
    t = encryptor.encrypt(a)
    print("t : \t\t\t\t%s"%(hexlify(t)))
    package1 = hexlify(a) + hexlify(t)

    print("a||t : \t\t\t\t%s" %(package1))

    forged = b'0000000000111000000000000000000066e94bd4ef8a2c3b884cfa59ca342b2e'
    print("Forged message : \t%s " % (forged))

    pPrime = decryptor.decrypt(forged)

    print("a' : \t\t\t\t%s "%(pPrime))
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    tPrime = encryptor.encrypt(pPrime)[32:]
    print("t' : \t\t\t\t%s"%(tPrime))



if __name__ == '__main__':
    main()