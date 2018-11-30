from Crypto.Cipher import AES
from Crypto.Hash import SHA


class Certificate(object):
    def __init__(self):
        print("Certificate created..")
        print("version: 1.0")
        print("Signature Algorithim: ")

    def hash(object):
        hasher = SHA.new(object.encode())
        return hasher

    def issuer(self):
        return "mssd classwork 12 qn1"


def main():
    cert = Certificate()
    cert.issuer()


if __name__ == '__main__':
    main()