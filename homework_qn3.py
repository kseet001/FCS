# Homework 5 - Question 3
# With your AES-CBC implementation encrypt 160MB of zeros:
# "\x00"*int(1.6*10**8)
# under 128-bit long zeroed key and IV. What is the last 128 bits of the ciphertext?
# Compare efficiency (time) of your implementation with a chosen library or tool that offers AES-CBC.

from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

plaintext = "\x00" * int(1.6 * 10 ** 8)
key = "\x00" * 16
IV = "\x00" * 16


class CustomAES:
    # TODO: implement custom AES-CBC algorithm class

    def __init__(self, key, IV):
        self.key = key
        self.IV = IV
        self.numOfRounds = 0

        print("Key : %s" % (self.key))
        print("Initialisation Vector : %s" % (self.IV))

        keySize = hexlify(self.key).__len__() / 2   # Divide by two because 2 hexdecimal makes 1 byte

        if keySize == 128:
            self.numOfRounds = 10
        elif keySize == 192:
            self.numOfRounds = 12
        elif keySize* 8 == 256:
            self.numOfRounds = 14

        print("Number of rounds : %s" % (self.numOfRounds))

    def encrypt(self, plaintext):
        # TODO: implement the algorithm for encrypting
        ciphertext = ""
        plaintext = plaintext.encode()

        # 1. XOR the first block of plaintext with IV
        print("Initialisation Vector : %s " % (self.IV))
        print("First block of plaintext : %s" % (hexlify(plaintext)[:32]))
        preblock = IV ^ plaintext

        # 2. Call the block encryption method with the key
        # 3. Pass the previous ciphertext and XOR with the second block of plaintext
        # 4. Call the block encryption method again
        # 5. Repeat 3. until end

        return ciphertext

    def __blockEncryption(self):
        """ To implement the AES block encryption algorithm """


    def pad(self, block):
        # TODO: To implement padding algorithm
        paddedData = ""
        return paddedData


def encrypt(plaintext):
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    return encryptor.encrypt(plaintext)


def main():
    # TODO: To compare the performance between our custom AES.CBC algorithm and the pycrypto library's

    # Print results from custom AES
    customCipher = CustomAES(hexlify(key.encode()), hexlify(IV.encode()))
    customCipher.encrypt(plaintext)



    '''
    # TODO: To print the last 128 bits (16 bytes) of the ciphertext
    ciphertext = encrypt(plaintext)
    # print(encrypt(plaintext))  # takes very long to print
    c1 = hexlify(ciphertext)
    c1 = c1[c1.__len__() - 32:]
    print("\nResults from pycrypto library:")
    print(unhexlify(c1))
    print(key.__len__())

    print("Done!")
    '''


if __name__ == '__main__':
    main()
