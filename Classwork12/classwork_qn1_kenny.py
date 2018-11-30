from Crypto.Cipher import AES
from Crypto.Hash import SHA
#from modules.RSA
import importlib
importlib.import_module("RSA.py")

class Certificate(object):

    def __init__(self):
        print("Certificate created..")
        print("version: 1.0")
        print("Signature Algorithim: ")
        self.subject = ...
        self.issuer = ...
        self.not_before = ...
        self.not_after = ...
        self.public_key = ...
        self.signature = ...

    def hash(object):
        hasher = SHA.new(object.encode())
        return hasher

    def issuer(self):
        return "mssd classwork 12 qn1"


class CA(object):
    def __init__(self, name):
        self.name = name

    def issue_certificate(self):
        ...

    def verify_certificate(self, certificate : Certificate):
        ...

    def revoke_certificate(self):
        ...


def main():
    cert = Certificate()
    cert.issuer()



if __name__ == '__main__':
    main()