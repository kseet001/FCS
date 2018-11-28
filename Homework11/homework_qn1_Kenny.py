import os
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

    def send(self, dest, msg):
        if dest == "KDC":
            return msg
        else:
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


if __name__ == '__main__':

    ''' Initialise the objects and the shared keys'''

    shared_key_A = 'SHARED_KEY_A1234'  # Shared key between Alice and KDC
    shared_key_B = 'SHARED_KEY_B1234'  # Shared key between Bob and KDC

    kdc = KDC(shared_key_A, shared_key_B)  # Initialising a KDC object with the shared keys of Alice and Bob
    alice = Alice(shared_key_A)  # Initialise Alice object
    bob = Bob(shared_key_B)  # Initialise Bob object

    ''' Simulating the key exchange '''

    print("\n===Start of PKI key exchange===\n")

    auth_request = "Alice, Bob"
    auth_request = alice.send("KDC", auth_request)     # Alice sends a request to KDC for a session between Alice and Bob
    print("Alice sends to KDC: ", auth_request)

    AS_response = kdc.auth_response(auth_request)
    print("KDC reply to Alice: ", AS_response)

    ticket = alice.process_auth_response(AS_response)
    print("\nAlice decrypts the response from KDC and obtained:")
    print("\tSession key: ", alice.session_key)
    print("\tTicket: ", ticket)

    print("\nAlice sends Ticket to Bob: ", ticket)
    bob.process_ticket(ticket)

    print("Bob decrypts the Ticket and obtained:")
    print("\tSession key: ", bob.session_key)

    print("\nBob uses the Session Key to encrypt 'Hello Alice' and sends to Alice:")
    msg1 = bob.send("Hello Alice")
    print("\tEncrypted message: ", msg1)

    print("\nAlice decrypts using the Session Key and gets:")
    print("\tDecrypted message from Bob: ", alice.receive(msg1))

    print("\nAlice uses the Session Key to encrypt 'Hi Bob!' and send to Bob")
    msg2 = alice.send("Bob", "Hi Bob")
    print("Alice sends: ", msg2)

    print("\nBob decrypts using the Session Key and gets: ")
    print("\tDecrypted message from Alice: ", bob.receive(msg2))

    print("\n===End of key exchange===")
