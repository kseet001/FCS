''' Question 2.
Compute any official test vector of HMAC-SHA256 (see https://tools.ietf.org/
html/rfc4868#section-2.7.2.1).
'''


import hashlib, hmac
from Crypto.Hash import SHA256, HMAC

print("\nQuestion 2)")

'''Test 1'''
print("\nTest1:")
key = "\x0b" * int(32)
data = "Hi There"
valid_hash = "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
hasher = HMAC.new(key.encode(),data.encode(),SHA256)
print("Key: \t\t\t\t%s" % (key.encode()))
print("Data: \t\t\t\t%s" % (data.encode()))
print("Valid hash: \t\t%s" % (valid_hash))
print("Hashed obtained: \t%s" % (hasher.hexdigest()))

'''Test 2'''
print("\nTest2:")
key = "JefeJefeJefeJefeJefeJefeJefeJefe"
data = "what do ya want for nothing?"
valid_hash = "167f928588c5cc2eef8e3093caa0e87c167f928588c5cc2eef8e3093caa0e87c"
hasher = HMAC.new(key.encode(),data.encode(),SHA256)
hasher = hmac.new(key.encode(),data.encode(),hashlib.sha256)
print("Key: \t\t\t\t%s" % (key.encode().hex()))
print("Data: \t\t\t\t%s" % (data.encode()))
print("Valid hash: \t\t%s" % (valid_hash))
print("Hashed obtained: \t%s" % (hasher.hexdigest()))

'''Test 3'''
print("\nTest3:")
key = "\x0a" * int(32)
data = "\x0d" * int(50)
valid_hash = "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0"
hasher = HMAC.new(key.encode(),data.encode(),SHA256)
print("Key: \t\t\t\t%s" % (key.encode()))
print("Data: \t\t\t\t%s" % (data.encode()))
print("Valid hash: \t\t%s" % (valid_hash))
print("Hashed obtained: \t%s" % (hasher.hexdigest()))