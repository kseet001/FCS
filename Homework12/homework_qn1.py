from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256, HMAC
from datetime import datetime
from datetime import timedelta
from Crypto.Cipher import PKCS1_v1_5 as PKCS1
from Crypto.Signature import PKCS1_v1_5 as PKCS2
import json
import random
import math
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from binascii import hexlify

# Choose a random, 16-byte IV.
iv = Random.new().read(AES.block_size)

# Convert the IV to a Python integer.
iv_int = int(hexlify(iv), 16)

class Peer(object):
    def __init__(self, key, name):

        self.name = name

        if name == "Alice":
            self.key_send_enc = SHA256.new((key + "Enc Alice to Bob").encode()).digest()
            self.key_recv_enc = SHA256.new((key + "Enc Bob to Alice").encode()).digest()
            self.key_send_auth = SHA256.new((key + "Auth Alice to Bob").encode()).digest()
            self.key_recv_auth = SHA256.new((key + "Auth Bob to Alice").encode()).digest()
        elif name == "Bob":
            self.key_send_enc = SHA256.new((key + "Enc Bob to Alice").encode()).digest()
            self.key_recv_enc = SHA256.new((key + "Enc Alice to Bob").encode()).digest()
            self.key_send_auth = SHA256.new((key + "Auth Bob to Alice").encode()).digest()
            self.key_recv_auth = SHA256.new((key + "Auth Alice to Bob").encode()).digest()
        elif name == "Eve":
            self.key_send_enc = SHA256.new((key + "Enc Bob to Alice").encode()).digest()
            self.key_recv_enc = SHA256.new((key + "Enc Alice to Bob").encode()).digest()
            self.key_send_auth = SHA256.new((key + "Enc Bob to Alice").encode()).digest()
            self.key_recv_auth = SHA256.new((key + "Enc Alice to Bob").encode()).digest()

        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        self.encryptor = AES.new(self.key_send_enc, AES.MODE_CTR, counter=ctr)
        self.decryptor = AES.new(self.key_recv_enc, AES.MODE_CTR, counter=ctr)


    def send(self, msg):
        mac = HMAC.new(self.key_send_auth, msg.encode(), SHA256).hexdigest() # calculate the mac of the msg

        protected_msg = self.encryptor.encrypt(msg + mac)

        #print("msg: ", msg)
        #print("mac: ", mac)
        print("%s sends: %s" %(self.name, protected_msg))

        return protected_msg # type of protected_msg is ’str’

    def receive(self, protected_msg):

        decrypted_msg = self.decryptor.decrypt(protected_msg)
        msg = decrypted_msg[:len(decrypted_msg)-64]
        mac1 = decrypted_msg[len(decrypted_msg)-64:]

        # check msg integrity
        mac2 = HMAC.new(self.key_recv_auth, msg, SHA256).hexdigest().encode()

        if mac1 == mac2:
            print(
                "%s decrypts and got the following message: %s" % (self.name, msg))  # successfully recovered plaintext
        else:
            print("%s decrypts and MAC did not match - Message has been tampered!" %(self.name))

        return msg

def is_prime(n):
    while True:
        isprime = True
        for x in range(2, int(math.sqrt(n) + 1)):
            if n % x == 0:
                isprime = False
                break

        if isprime:
            break

        n += 1
    return n

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
        signer = PKCS1.new(issuer_private_key)
        #self.signature = signer.sign(h)
        self.signature = signer.encrypt(h.digest())


    def get_cert_without_sig(self):
        return self.subject +" "+ self.issuer +" "+ str(self.not_before) +" "+ str(self.not_after) +" "+ str(self.public_key)

    def get_cert(self):
        return self.subject +" "+ self.issuer +" "+ str(self.not_before) +" "+ str(self.not_after) +" "+ str(self.public_key) +" "+ str(self.signature)

class person():
    def __init__(self):
        self.root_key = ""
        self.root_CA = ""
        self.server_key = ""

        self.sharedPrivateKey= ""
        self.Message= ""

    def getCertificate(self, subject, issuer):
        self.root_key, self.server_key = RSA.generate(2048), RSA.generate(2048)
        self.root_CA = Certificate()
        self.root_CA.create_certificate(subject, issuer, self.root_key, self.root_key)
        return self.root_CA.get_cert()

    def sharedPrivate(self, key):
        self.sharedPrivateKey = key

    def getSharedPrivate(self):
        return self.sharedPrivateKey

    def sendMessage(self, message):
        self.Message = message

    def getMessage(self, text):
        return self.Message

    def checkCertificate(self, cert):
        cert_attributes = cert.decode('UTF-8').split(" ")
        for i in range(len(cert_attributes)):
            print(cert_attributes[i])
        return 0

def keyNegotiation():
    key_A = RSA.generate(2048)
    key_B = RSA.generate(2048)

    # Alice
    S_alice = 3
    N = random.randint(0, (2 ** 256) - 1)
    print("Alice sends S_alice=", S_alice, " N= ", N)
    print()

    # Bob
    S_bob = 3
    s = max(S_alice, S_bob)
    assert s <= 2 * S_bob
    # Bob Chooses (g,p,q)
    q = 5
    p = 2 * q + 1
    alpha = random.randint(2, p - 2)
    g = alpha ** 2 % p
    # assert
    assert g != 1
    assert g != (p - 1)
    b = random.randint(1, q - 1)
    B = g ** b % p

    s_str = str(N)

    # Bob send
    h = SHA.new(s_str.encode())
    signer = PKCS2.new(key_B)
    signature = signer.sign(h)
    print("Bob sends: (g,p,q) = (", g, p, q, ") B=", B, " AUTHbob=", signature)
    print()

    # Alice receive
    h = SHA.new(s_str.encode())
    verifier = PKCS2.new(key_B)
    # Alice checks AUTHbob
    if verifier.verify(h, signature):
        print("Bob's signature is valid")
    else:
        print("Bob's signature is not valid")

    # Assert
    assert (S_alice - 1) <= math.log(p, 2)
    assert math.log(p, 2) <= 2 * S_alice
    assert 2 <= math.log(q, 2) <= 3
    assert p == is_prime(p)
    assert q == is_prime(q)
    assert q | (p - 1) ^ g != 1 ^ (g ** q == 1)
    assert B != 1 ^ (B ** q != 1)
    a = random.randint(1, q - 1)
    A = g ** a % p

    h = SHA.new(s_str.encode())
    signer = PKCS2.new(key_A)
    signature = signer.sign(h)
    Kp = (B ** a) % p
    alice_K = SHA256.new(str(Kp).encode()).hexdigest()
    print("Alice sends: A=", A, " AUTHalice=", signature)
    print()

    # Send to Bob
    h = SHA.new(s_str.encode())
    verifier = PKCS2.new(key_A)

    # Bob checks AUTHalice
    if verifier.verify(h, signature):
        print("Alice's signature is valid")
    else:
        print("Alice's signature is not alid")
    assert A != 1
    assert A ** q % p == 1

    Kp2 = (A ** b) % p
    bob_K = SHA256.new(str(Kp2).encode()).hexdigest()
    return alice_K, bob_K


def main():
    print("\nAlice communicates with server")
    print("Server sends Alice the server's certificate")
    alice = person()
    a_certificate = alice.getCertificate("root", "root")
    print("Alice obtained: ")
    print(a_certificate)

    print("\nBob communicates with server")
    print("Server sends Bob the server's certificate")
    bob = person()
    b_certificate = bob.getCertificate("root", "root")
    print("Bob obtained: ")
    print(b_certificate)
    print("\n\n")

    print("========================\t\t Initiating Key Negotiation Protocol \t\t========================")
    alice_K, bob_K = keyNegotiation()
    alice.sharedPrivate(alice_K)
    bob.sharedPrivate(bob_K)
    print("Alice's key computation= %s\nBob's key computation= = %s" % (alice.getSharedPrivate(), bob.getSharedPrivate()))

    print("========================\t\t End of Key Negotiation \t\t========================")
    print("\n\n")


    print("========================\t\t Secure Channel Communication using shared key \t\t========================")
    print("\nSetting up Secure channel with shared Key...")
    alice_p = Peer(alice.getSharedPrivate(), "Alice")
    bob_p = Peer(bob.getSharedPrivate(), "Bob")

    print("\nAlice sends Bob its Certificate:")
    alice_cert = alice_p.send(a_certificate)
    alice_msg = bob_p.receive(alice_cert)
    #bob check alice certificiate authenticity
    bob.checkCertificate(alice_msg)

    print("\nBob sends Alice its Certificate:")
    bob_cert = bob_p.send(b_certificate)
    bob_msg= alice_p.receive(bob_cert)
    #Alice checks bobs certificate authenticity
    alice.checkCertificate(bob_msg)

    #Bob Check Alice's certificate authenticity


"""


    print("\nAlice wants to verify the signature:")
    print(server.signature)

    print("\nAlice get public key of the root CA:")
    print(root_CA.public_key)

    json_str = json.dumps(server.get_cert_without_sig())
    h = SHA.new(json_str.encode()).digest()

    checker = PKCS1.new(root_CA.public_key)
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

    checker = PKCS1.new(root_CA.public_key)
    tmp = checker.decrypt(root_CA.signature, root_CA.sentinel)
    print("\n Alice verifies the signature: ")
    print("Decrypted signature: ", tmp)
    print("Hash of certificate without signature: ", h)
    if tmp == h:
        print("OK - CA verified")
    else:
        print("NOT OK")
    print("========================\t\t End of Certificate issuance \t\t========================")


    
"""
if __name__ == '__main__':
    main()