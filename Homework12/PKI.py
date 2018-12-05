from datetime import datetime
from datetime import timedelta
import json
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_PSS as PKCS1
from Crypto.PublicKey import RSA


class CA(object):

    def __init__(self, name, private_key):
        self.CA_name = name
        self.CA_private_key = private_key
        self.CA_public_key = private_key.publickey()
        self.signature = ""

    def create_certificate(self, subject, subject_public_key):
        subject = subject
        issuer = self.CA_name
        not_after = datetime.now() + timedelta(days=3)
        not_before = datetime.now()
        public_key = subject_public_key
        # self.public_key = public_key

        cert = {
            "subject": subject,
            "issuer": issuer,
            "not after": str(not_after),
            "not before": str(not_before),
            "public key": str(public_key)
        }

        json_str = json.dumps(cert)
        h = SHA.new(json_str.encode())
        signer = PKCS1.new(self.CA_private_key)
        self.signature = signer.sign(h)
        cert['CA signature'] = self.signature

        return cert

    def get_public_key(self):
        return self.CA_public_key


class Person(object):

    def __init__(self, name):
        self.name = name
        self.session_key = ""

    def verify_cert(self, certificate: dict, issuer_public_key):
        verifier = PKCS1.new(issuer_public_key)
        signature = certificate['CA signature']
        body = certificate.copy()
        try:
            del body['CA signature']
        except KeyError:
            print("signature field not found")

        json_str = json.dumps(body)
        h = SHA.new(json_str.encode())

        if verifier.verify(h, signature):
            return True
        else:
            return False


if __name__ == '__main__':
    # for testing purpose
    root_key = RSA.generate(2048)
    root_ca = CA("root", root_key)
    alice_key = RSA.generate(2048)
    bob_key = RSA.generate(2048)

    alice = Person("Alice")
    bob = Person("Bob")

    alice_cert = root_ca.create_certificate("alice", alice_key.publickey().exportKey('PEM'))
    bob_cert = root_ca.create_certificate("bob", bob_key.publickey().exportKey('PEM'))

    print(alice_cert)
    print(bob_cert)

    # Alice sends Bob her Certificate
    issuer_key = root_ca.get_public_key()
    bob.verify_cert(alice_cert, issuer_key)
