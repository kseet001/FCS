from Crypto.Cipher import AES
from binascii import hexlify

''' Define the plaintext, IV and key '''
key = b"\x00" * 16  # 128 bits key
IV = b"\x00" * 16  # 128 bits IV

def main():
    a = "hello world. 123".encode()

    print("\n=== 1. Original Message ===")
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    t = encryptor.encrypt(a)
    print("\t\ta : \t%s" % (hexlify(a)))
    print("MAC(a), t : \t%s"%(hexlify(t)))
    print("\t a||t : \t%s"%(hexlify(a + t)))

    print("\n=== 2. Forging Message ===")
    print("Finding b, such that (b XOR t)=a...")
    a = bytearray(a)
    t = bytearray(t)
    aPrime = bytearray(len(a))

    for i in range(len(a)):
        aPrime[i] = a[i] ^ t[i]

    print("b : \t%s" % (hexlify(bytes(aPrime))))

    print("\n=== 3. Forged Message ===")
    message2 = bytes(a) + bytes(aPrime)
    print("\t\t\t\t\t\ta||b : \t%s" %(hexlify(message2)))
    print("# Attacker will send a||b||t : \t%s"%(hexlify(message2 + t)))

    print("\n=== 4. Receiver calculating MAC of a||b ===")
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    tPrime = encryptor.encrypt(message2)[16:]
    print("MAC(a||b) : %s" % (hexlify(tPrime)))
    print("MAC(a), t : %s" % (hexlify(t)))
    print("# Message a and a||b produces the same message tag.")


if __name__ == '__main__':
    main()