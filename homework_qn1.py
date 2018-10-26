# Homework 5 - Question 1
# Encrypt the following plaintext P (represented with 8-bit ASCII) using AES-ECB,
# with the key of 128-bit 0. You may use an existing crypto library for this exercise.
# P = SUTD-MSSD-51.505*Foundations-CS*

from Crypto.Cipher import AES
from binascii import hexlify, unhexlify


plaintext = "SUTD-MSSD-51.505*Foundations-CS*"
key = '\x00' * 16


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')


def encrypt(key, plaintext):
    encryptor = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return encryptor.encrypt(plaintext.encode('utf-8'))


def decrypt(key, ciphertext):
    decryptor = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return decryptor.decrypt(ciphertext)


# AES requires that plaintexts be a multiple of 16, so we have to pad the data
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


def solve_1a():
    ciphertext = encrypt(key, plaintext)

    print("\nQuestion 1a)")
    print("C : %s" % (hexlify(ciphertext)))


def solve_1b():
    ciphertext = encrypt(key, plaintext)

    print("\nQuestion 1b)")
    C = hexlify(ciphertext)
    C1 = C[0:32]
    C2 = C[32:]

    P1 = decrypt(key, unhexlify(C2+C1))
    print("P1 : %s" % (P1.decode("utf-8")[:16]))


def solve_1c():

    ciphertext = encrypt(key, plaintext)
    C = hexlify(ciphertext)
    C1 = C[0:32]
    C2 = C[32:]

    # Convert to int, increment by 1 and convert back to bytes
    C2_modified = int_from_bytes(C2) + 1
    C2_modified = int_to_bytes(C2_modified)



    print("\nQuestion 1c)")

    #print("Original ciphertext: %s" % (unhexlify(C1+C2)))             # for debugging purpose
    #print("Modified ciphertext: %s" % (unhexlify(C1+C2_modified)))     # for debugging purpose - shows that it has been incremented by 1

    P2 = decrypt(key, unhexlify(C1+C2_modified))
    print("P2 : %s" % (P2)[16:])
    P2 = decrypt(key, unhexlify(C1 + C2))   # for debugging purpose
    print("P2 : %s" % (P2)[16:])    # for debugging purpose



def main():

    print("\nP : %s" % (plaintext.encode()))
    print("Key : %s" % (key.encode()))

    solve_1a()
    solve_1b()
    solve_1c()


if __name__ == "__main__":
    main()