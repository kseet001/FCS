''' Question 1.
Hash "51.505-Foundations-of-Cybersecurity-MSSD" and
"51.505-Foundations-of-Cybersecurity-MSSd", respectively using SHA1.
Observe the difference of these 2 hash values.
'''

from Crypto.Hash import SHA

plaintext1 = "51.505-Foundations-of-Cybersecurity-MSSD"
plaintext2 = "51.505-Foundations-of-Cybersecurity-MSSd"

print("\nQuestion 1)")
hasher = SHA.new(plaintext1.encode())
print("\nSHA1 hash of '%s':" % (plaintext1))
#print(hasher.digest())
print(hasher.hexdigest())

print("\nSHA1 hash of '%s':" % (plaintext2))
hasher = SHA.new(plaintext2.encode())
#print(hasher.digest())
print(hasher.hexdigest())