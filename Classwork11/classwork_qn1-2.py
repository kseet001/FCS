#(Final, Long)

import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
import math


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

key_A = RSA.generate(2048)
key_B = RSA.generate(2048)

#Alice
Sa = 3
N = random.randint(0,(2**256)-1)
print("Alice sends Sa=", Sa," N= ", N)
print()

#Bob
Sb = 3
s = max(Sa,Sb)
assert s<=2*Sb
# Bob Chooses (g,p,q)
q = 5
p=2*q+1
alpha = random.randint(2,p-2)
g = alpha**2%p
#assert
assert g!=1
assert g!=(p-1)
b = random.randint(1,q-1)
B = g**b%p

s_str = str(N)

# Bob send
h = SHA.new(s_str.encode())
signer = PKCS1_v1_5.new(key_B)
signature = signer.sign(h)
print("Bob sends: (g,p,q) = (",g,p,q,") B=",B," AUTHbob=",signature)
print()

# Alice receive
h = SHA.new(s_str.encode())
verifier = PKCS1_v1_5.new(key_B)
#Alice checks AUTHbob
if verifier.verify(h,signature):
    print("Bob's signature is valid")
else:
    print("Bob's signature is not valid")

# Assert
assert (Sa-1)<=math.log(p,2)
assert math.log(p,2)<=2*Sa
assert 2<=math.log(q,2)<=3
assert p == is_prime(p)
assert q == is_prime(q)
assert q|(p-1)^g!=1^(g**q==1)
assert B!=1^(B**q!=1)
a = random.randint(1,q-1)
A=g**a%p

h = SHA.new(s_str.encode())
signer = PKCS1_v1_5.new(key_A)
signature = signer.sign(h)
Kp=(B**a)%p
alice_K = SHA256.new(str(Kp).encode()).hexdigest()
print("Alice sends: A=",A," AUTHalice=",signature)
print()

# Send to Bob
h = SHA.new(s_str.encode())
verifier = PKCS1_v1_5.new(key_A)

#Bob checks AUTHalice
if verifier.verify(h,signature):
    print("Alice's signature is valid")
else:
    print("Alice's signature is not alid")
assert A!=1
assert A**q%p==1

Kp2=(A**b)%p
bob_K = SHA256.new(str(Kp2).encode()).hexdigest()

print()
print("Alice's key computation= %s\nBob's key computation= = %s" % (alice_K, bob_K))