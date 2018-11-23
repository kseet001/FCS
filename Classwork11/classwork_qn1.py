#(Final, Short)

import random
from Crypto.Hash import SHA

q_pub = 2
p_pub = 2*q_pub + 1
phi_pub = random.randint(2, p_pub-2)
g_pub = (phi_pub**2) % p_pub

# Alice
n = random.randint(0, (2**256) - 1)
print("Alice sends: ", p_pub, n)
print()

#Bob
b = random.randint(1, q_pub-1)
B = g_pub**b % p_pub
bobHashedMsg = SHA.new(str(B).encode()).hexdigest()
print("Bob sends: ",g_pub,p_pub,q_pub,B,bobHashedMsg)


print()
#Alice
print("ALice checks Bobs Message")

aliceCheck = SHA.new(str(B).encode()).hexdigest()

if aliceCheck == bobHashedMsg:
    print("Alice Checks Bob's Message = Valid")
else:
    print("Alice Checks Bob's Message = inValid")

a = random.randint(1, q_pub-1)
A = g_pub**a % p_pub
alice_kPrime = B ** a % p_pub
k_alice = SHA.new(str(alice_kPrime).encode())

print("Alice's K= ", k_alice.hexdigest())
aliceHashedMsg = SHA.new(str(A).encode()).hexdigest()
print("Alice sends: ", A,aliceHashedMsg)

print()
#Bob
bobCheck = SHA.new(str(A).encode()).hexdigest()

if bobCheck == aliceHashedMsg:
    print("Bob Checks Alice's Message = Valid")
else:
    print("Bob Checks Alice's Message = Valid")

bob_kPrime = A**b % p_pub
k_bob = SHA.new(str(bob_kPrime).encode())
print("Bob's K= ", k_bob.hexdigest())