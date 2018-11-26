import sys
import os
import random
import base64
from Crypto.Cipher import AES


class Alice:
    def __init__(self, shared_key_A):
        self.name = "Alice"
        self.cipher = AESCipher(shared_key_A)  # This is the shared key between Alice and the PKI server
        self.session_key = ""  # shared session key between Alice and Bob. This is obtained from PKI server

    def process_auth_response(self, encrypted_session_key):
        decrypted__msg = self.cipher.decrypt(encrypted_session_key)
        self.session_key = decrypted__msg[:32]
        ticket = decrypted__msg[32:]
        return ticket

    def process_ticket(self, ticket):
        self.session_key = self.cipher.decrypt(ticket)

    def send(self, msg):
        ciphertext = AESCipher(self.session_key).encrypt(msg)
        return ciphertext

    def receive(self, msg):
        plaintext = AESCipher(self.session_key).decrypt(msg)
        return plaintext


class Bob:

    def __init__(self, shared_key_B):
        self.name = "Bob"
        self.cipher = AESCipher(shared_key_B)  # This is the shared key between Bob and the PKI server
        self.session_key = ""  # Shared session key between Alice and Bob. This is obtained from PKI server

    def process_auth_response(self, encrypted_session_key):
        decrypted__msg = self.cipher.decrypt(encrypted_session_key)
        self.session_key = decrypted__msg[:32]
        ticket = decrypted__msg[32:]
        return ticket

    def process_ticket(self, ticket):
        self.session_key = self.cipher.decrypt(ticket)

    def send(self, msg):
        ciphertext = AESCipher(self.session_key).encrypt(msg)
        return ciphertext

    def receive(self, msg):
        plaintext = AESCipher(self.session_key).decrypt(msg)
        return plaintext


class KDC:

    def __init__(self, shared_key_alice, shared_key_bob):
        self.cipher_alice = AESCipher(shared_key_alice)
        self.cipher_bob = AESCipher(shared_key_bob)

    def _generate_ticket(self, requester: str):
        if requester == "Alice":
            session_key = os.urandom(16)
            session_key = session_key.hex()
            # session_key = str(base64.b64encode(session_key), 'utf-8')
            ticket = self.cipher_bob.encrypt(session_key)
        else:
            session_key = os.urandom(16)
            session_key = str(base64.b64encode(session_key), 'utf-8')
            ticket = self.cipher_alice.encrypt(session_key)

        return ticket, session_key

    def auth_response(self, message: str):
        requester, receiver = message.rsplit(",")
        ticket, session_key = self._generate_ticket(requester)
        # session_key = os.urandom(16)

        if requester == "Alice":
            return self.cipher_alice.encrypt(session_key + ticket)
        else:
            return self.cipher_bob.encrypt(session_key + ticket)


class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, raw):
        raw = self._pad(raw)
        encrypted = self.cipher.encrypt(raw.encode())
        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')

    def decrypt(self, raw):
        decoded = base64.b64decode(raw)
        decrypted = self.cipher.decrypt(decoded)
        return str(self._unpad(decrypted), 'utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]


def main():
    shared_key_A = 'SHARED_KEY_A1234'
    shared_key_B = 'SHARED_KEY_B1234'

    kdc = KDC(shared_key_A, shared_key_B)
    alice = Alice(shared_key_A)
    bob = Bob(shared_key_B)

    print("\n===Start of PKI key exchange===")
    print("\n1) Alice sends a request to the PKI Server to establish a secure session with Bob")
    auth_request = "Alice, Bob"
    print("Alice sends: ", auth_request)


    print("\n2) KDC sends back an authentication response, with a session key and ticket, both encrypted with the shared key between Alice and KDC")
    AS_response = kdc.auth_response("Alice, Bob")
    print("Response from KDC: ", AS_response)


    print("\n3) Alice decrypts the authentication response from the KDC and obtain the session key and a ticket")
    ticket = alice.process_auth_response(AS_response)
    print("Session key obtained: ", alice.session_key)
    print("Ticket obtained: ", ticket)

    print("\n4) Alice sends Bob the ticket, which was encrypted with the shared key between Bob and KDC")
    print("Alice sends: ", ticket)
    bob.process_ticket(ticket)

    print("\n5) Bob decrypts the ticket and obtains the session key")
    print("Session key obtained: ", bob.session_key)

    print("\n6) Bob uses the session key and send a message to Alice")
    msg1 = bob.send("Hello Alice")
    print("Bob sends: ", msg1)

    print("\n7) Alice decrypts and gets: ", alice.receive(msg1))

    print("\n8) Alice uses the session key and send a message to Bob")
    msg2 = alice.send("Hello Bob! Here is my secret message")
    print("Alice sends: ", msg2)

    print("\n9) Bob decrypts and gets: ", bob.receive(msg2))

    print("\n===End of key exchange===")

    '''
    print("[Alice] Initiating KDC Process...")
    plaintext = 'Alice, Bob'
    print("[Alice] User: Alice, Requesting communication to : Bob")
    encrypted = cipher.encrypt(plaintext)
    print("[Alice] Sending authentication to KDC....")
    ticket = KDC(encrypted)
    print("[Alice] Ticket received.. authenticating ticket with TGT server...")
    token = TGT(ticket)
    print("[Alice] Received token: ", token, " from TGT...")
    print("[Alice] initiating communication with Bob..")
    bob(token, "i want to initiate connection.")
    '''


if __name__ == '__main__':
    main()
