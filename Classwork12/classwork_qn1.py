from Crypto.Cipher import AES
from Crypto.Hash import SHA
from datetime import datetime
from datetime import timedelta
import RSA


class Certificate:

    @staticmethod
    def __init__(self):
        print("Certificate created..")
        print("version: 1.0")

    @staticmethod
    def subject(self):
        print("Owner of Certificate: WE ARE THE OWNER!")

    @staticmethod
    def signature(message):
        sign = RSA()
        p = 17
        q = 19
        public, private = sign.generate_keypair(p, q)
        #message = message
        encrypted_msg = sign.encrypt(private, message)
        return encrypted_msg

    @staticmethod
    def issuer(self):
        return "mssd classwork 12 qn1"

    @staticmethod
    def notAfter(self):
        endDate = datetime.now() + timedelta(days=3)
        return endDate

    @staticmethod
    def notBefore(self):
        startDate = datetime.now()
        return startDate

    @staticmethod
    def pubKey(self):
        print("pubKey")


class RSA():

    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def modinv(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception('No modular inverse')
        return x % m

    def is_prime(num):
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num ** 0.5) + 2, 2):
            if num % n == 0:
                return False
        return True

    def generate_keypair(p, q):
        if not (is_prime(p) and is_prime(q)):
            raise ValueError('Both numbers must be prime.')
        elif p == q:
            raise ValueError('p and q cannot be equal')
        # n = pq
        n = p * q

        # Phi is the totient of n
        phi = (p - 1) * (q - 1)

        # Choose an integer e such that e and phi(n) are coprime
        e = random.randrange(1, phi)

        # Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g = gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = gcd(e, phi)

        # Use Extended Euclid's Algorithm to generate the private key
        d = modinv(e, phi)

        # Return public and private keypair
        # Public key is (e, n) and private key is (d, n)
        return ((e, n), (d, n))

    def encrypt(pk, plaintext):
        # Unpack the key into it's components
        key, n = pk
        # Convert each letter in the plaintext to numbers based on the character using a^b mod m
        cipher = [(ord(char) ** key) % n for char in plaintext]
        # Return the array of bytes
        return cipher

    def decrypt(pk, ciphertext):
        # Unpack the key into its components
        key, n = pk
        # Generate the plaintext based on the ciphertext and key using a^b mod m
        plain = [chr((char ** key) % n) for char in ciphertext]
        # Return the array of bytes as a string
        return ''.join(plain)


def main():
    cert = Certificate()
    cert.signature()



if __name__ == '__main__':
    main()