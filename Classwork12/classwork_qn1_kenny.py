from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from datetime import datetime
from datetime import timedelta
from Crypto.Cipher import PKCS1_v1_5
#from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
import json

class Certificate(object):

    def __init__(self):
        self.subject = ""
        self.issuer = ""
        self.not_before = ""
        self.not_after = ""
        self.public_key = ""
        self.signature = ""
        self.sentinel = ""


    def create_certificate(self, subject, issuer, public_key, issuer_private_key):

        self.not_after = datetime.now() + timedelta(days=3)
        self.not_before = datetime.now()
        self.subject = subject
        self.issuer = issuer
        #self.public_key = public_key.publickey().exportKey('PEM')
        self.public_key = public_key

        cert_string = self.subject + self.issuer + str(self.not_before) + str(self.not_after) + str(self.public_key) + str(self.signature)
        json_str = json.dumps(cert_string)

        h = SHA.new(json_str.encode())
        dsize = h.digest_size
        self.sentinel = Random.new().read(15+dsize)
        signer = PKCS1_v1_5.new(issuer_private_key)
        #self.signature = signer.sign(h)
        self.signature = signer.encrypt(h.digest())


    def get_cert_without_sig(self):
        return self.subject + self.issuer + str(self.not_before) + str(self.not_after) + str(self.public_key)

    def get_cert(self):
        return self.subject + self.issuer + str(self.not_before) + str(self.not_after) + str(self.public_key) + str(self.signature)


def main():

    root_key, server_key = RSA.generate(2048), RSA.generate(2048)
    root_CA = Certificate()
    root_CA.create_certificate("root", "root", root_key, root_key)
    #print(root_CA.get_cert())

    #print("")
    server = Certificate()
    server.create_certificate("server", "root", server_key, root_key)
    #print(server.get_cert())

    print("\nAlice communicates with server")
    print("Server sends Alice the server's certificate")

    print("\n\n=== Checking server cert ===")

    print("\nAlice obtained: ")
    print(server.get_cert())

    print("\nAlice wants to verify the signature:")
    print(server.signature)

    print("\nAlice get public key of the root CA:")
    print(root_CA.public_key)

    json_str = json.dumps(server.get_cert_without_sig())
    h = SHA.new(json_str.encode()).digest()

    checker = PKCS1_v1_5.new(root_CA.public_key)
    tmp = checker.decrypt(server.signature, server.sentinel)
    print("\n Alice verifies the signature: ")
    print("Decrypted signature: ", tmp)
    print("Hash of certificate without signature: ", h)
    if tmp == h:
        print("OK - Server verified")
    else:
        print("NOT OK")

    ''' Checking root cert '''

    print("\n\n=== Checking root cert ===")
    print("\nAlice obtained: ")
    print(root_CA.get_cert())

    print("\nAlice wants to verify the signature:")
    print(root_CA.signature)

    print("\nAlice get public key of the root CA:")
    print(root_CA.public_key)

    json_str = json.dumps(root_CA.get_cert_without_sig())
    h = SHA.new(json_str.encode()).digest()

    checker = PKCS1_v1_5.new(root_CA.public_key)
    tmp = checker.decrypt(root_CA.signature, root_CA.sentinel)
    print("\n Alice verifies the signature: ")
    print("Decrypted signature: ", tmp)
    print("Hash of certificate without signature: ", h)
    if tmp == h:
        print("OK - CA verified")
    else:
        print("NOT OK")


if __name__ == '__main__':
    main()