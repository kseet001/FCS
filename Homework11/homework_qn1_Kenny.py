import sys
import os
import base64
from Crypto.Cipher import AES


class Alice:
    def __init__(self, shared_key_A):
        self.name = "Alice"
        self.cipher = AESCipher(shared_key_A)
        self.session_key = ""

    def get_session_key(self, encrypted_session_key):
        self.session_key = self.cipher.decrypt(encrypted_session_key)
        return self.session_key


class Bob:

    def __init__(self, shared_key_B):
        self.name = "Bob"
        self.shared_key_B = shared_key_B


class KDC:

    def __init__(self, shared_key_alice, shared_key_bob):
        self.cipher_alice = AESCipher(shared_key_alice)
        self.cipher_bob = AESCipher(shared_key_bob)

    '''
    def _generate_ticket(self, requester: str):
        if requester == "Alice":
            session_key = os.urandom(16)
            ticket = self.cipher_bob.encrypt("Alice" + str(session_key))
        else:
            session_key = os.urandom(16)
            ticket = self.cipher_alice.encrypt("Alice" + str(session_key))

        return ticket, session_key
    '''

    def auth_response(self, message: str):
        requester, receiver = message.rsplit(",")
        print("[AS] KDC-AS Received a request from: ", requester, "to: ", receiver)
        #ticket, session_key = self._generate_ticket(requester)
        session_key = os.urandom(16)
        print("Generated session key: ", session_key)

        if requester == "Alice":
            return self.cipher_alice.encrypt(str(session_key))
        else:
            return self.cipher_bob.encrypt(str(session_key))


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

    print("[Alice] Requests for a session key from KDC")
    encrypted_session_key = kdc.auth_response("Alice, Bob")
    alice.get_session_key(encrypted_session_key)
    print("Session key:", alice.session_key)


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
