# Homework 5 - Question 2
# The ciphertext (in hex)
# 87 F3 48 FF 79 B8 11 AF 38 57 D6 71 8E 5F 0F 91
# 7C 3D 26 F7 73 77 63 5A 5E 43 E9 B5 CC 5D 05 92
# 6E 26 FF C5 22 0D C7 D4 05 F1 70 86 70 E6 E0 17
# was generated with the 256-bit AES key (also hex)
# 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
# using CBC mode with a random IV. The IV is included at the beginning of the
# ciphertext. Decrypt this ciphertext. You may use an existing crypto library for this exercise.

from Crypto.Cipher import AES

# 256 bit ciphertext
ciphertext = b'\x7C\x3D\x26\xF7\x73\x77\x63\x5A\x5E\x43\xE9\xB5\xCC\x5D\x05\x92' \
             b'\x6E\x26\xFF\xC5\x22\x0D\xC7\xD4\x05\xF1\x70\x86\x70\xE6\xE0\x17'

# 256 bit key
key = b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'

# 128 bit IV
IV = b'\x87\xF3\x48\xFF\x79\xB8\x11\xAF\x38\x57\xD6\x71\x8E\x5F\x0F\x91'


def decrypt(ciphertext):
    # TODO: implement decryptor to decipher
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    return decryptor.decrypt(ciphertext)


def main():
    # TODO implement controls
    print("\nQuestion 2)")
    print("Decrypted ciphertext: \n%s" % (decrypt(ciphertext).decode("utf-8")))


if __name__ == '__main__':
    main()
