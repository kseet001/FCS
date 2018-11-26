import sys
import base64
from Crypto.Cipher import AES



class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, raw):
        raw = self._pad(raw)
        encrypted = self.cipher.encrypt(raw)
        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')

    def decrypt(self, raw):
        decoded = base64.b64decode(raw)
        decrypted = self.cipher.decrypt(decoded)
        return str(self._unpad(decrypted), 'utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


key_kdc_user = '`?.F(fHbN6XK|j!t'
key_as_tgt = '`?.F(fHbN6XK|j!q'
key_tgs_receiver = '`?.F(fHbN6XK|j!z'

cipher = AESCipher(key_kdc_user)
cipher2 = AESCipher(key_as_tgt)
cipher3 = AESCipher(key_tgs_receiver)

def main():
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

def KDC(encrypted):

    decrypted = cipher.decrypt(encrypted)
    requester, access = decrypted.split(',')
    print("[AS] KDC-AS Received a request from: ", requester, "on: ", access)
    ticket = cipher2.encrypt("USER VERIFIED")
    print("[AS] User has been verified. responding with a Ticket..")
    return ticket

def TGT(request):
    decrypted = cipher2.decrypt(request)
    if decrypted == "USER VERIFIED":
        token = cipher3.encrypt("USER ALLOWED")
        print("[TGT] Granting token to access to Bob...")
        return token
    else:
        print("UNAUTHORIZED ACCESS")

def bob(ticket, request):
    decrypted = cipher3.decrypt(ticket)
    if decrypted == "USER ALLOWED":
        print("[Bob] You may fulfil your request on: ", request)

if __name__ == '__main__':
    main()
