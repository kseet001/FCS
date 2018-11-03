import os, random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA

key = 0x56e47a38c5598974bc46903dba290349       # 16 bytes, 128 bits
IV = 0x8ce82eefbea0da3c44699ed7db51b7d9         # 16 bytes, 128 bits
plaintext = 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
expected_ciphertext = 0xc30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')


def encrypt(key, plaintext):
    encryptor = AES.new(int_to_bytes(key), AES.MODE_CBC, int_to_bytes(IV))
    ciphertext = encryptor.encrypt(int_to_bytes(plaintext))
    return ciphertext


def compare(ciphertext):
    print("Comparing the ciphertext...")
    print("Expected ciphertext: %s" % (expected_ciphertext))
    print("Ciphertext received: %s\n" % (ciphertext))

    if expected_ciphertext == ciphertext:
        print ("AES CBC mode is successfully implemented")
    else:
        print("There is an error with the implementation")

def main():
    print("Key: \t\t\t%s" % (key))
    print("IV: \t\t\t%s" % (IV))
    print("Plaintext: \t\t%s" % (plaintext))

    ciphertext = encrypt(key, plaintext)
    ciphertext = int_from_bytes(ciphertext)

    print("Ciphertext: \t%s\n" % (ciphertext))

    # Compare the results
    compare(ciphertext)


if __name__ == "__main__":
    main()