from Crypto.Cipher import AES
from binascii import hexlify

''' Define the plaintext, IV and key '''
#m1 = b"\xa0" * int(16)  # 16 bytes
key = b"\x00" * 16  # 128 bits key
IV = b"\x00" * 16  # 128 bits IV

def main():
    ### Plaintext a is being transmitted
    a = b"\x00" * int(16)
    encryptor = AES.new(key,AES.MODE_CBC, IV)
    decryptor = AES.new(key,AES.MODE_CBC,IV)

    print("a : \t\t\t\t%s"%(hexlify(a)))
    ### prior transmission, MAC t is generated from plaintext a
    t = encryptor.encrypt(a)
    print("t : \t\t\t\t%s"%(hexlify(t)))

    ### tag t is appended to orginal message before transmission
    package1 = hexlify(a) + hexlify(t)
    print("a||t : \t\t\t\t%s" %(package1))

    ### an attacker intercepts the message and modify the content of the ciphertext excluding the last block to obtain a' ||t
    forged = b'0000000000111000000000000000000066e94bd4ef8a2c3b884cfa59ca342b2e'
    print("Forged message : \t%s " % (forged))

    ### receiver received a forged message and decrypts it obtaining a'
    pPrime = decryptor.decrypt(forged)
    print("a' : \t\t\t\t%s "%(pPrime))

    ### The receiver proceeds to compute the Tag for the message.
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    tPrime = encryptor.encrypt(pPrime)[32:]
    print("t' : \t\t\t\t%s"%(tPrime))


if _name_ == '_main_':
    main()