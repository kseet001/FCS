from Crypto.Hash import SHA256, HMAC
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




# Example
alice = Peer("very secret key!", "Alice")
bob = Peer("very secret key!", "Bob")
eve = Peer("unknown key12345", "Eve")

print("\nMessage 1:")
msg1 = alice.send("Msg from alice to bob")
bob.receive(msg1)
eve.receive(msg1)

print("\nMessage 2:")
msg2 = alice.send("Another msg from alice to bob")
bob.receive(msg2)
eve.receive(msg2)

print("\nMessage 3:")
msg3 = bob.send("Hello alice")
alice.receive(msg3)
eve.receive(msg3)