
# Diffie-Hellman protocol

# Publicly known info
sharedPrime = 23
sharedBase = 5

print("Shared prime: ", sharedPrime)
print("shared base: ", sharedBase)

print()

# Seret information
a_secret = 6
b_secret = 15

# Transmission and Computation
a_send = (sharedBase ** a_secret) % sharedPrime
b_compute = a_send ** b_secret
bobSends = (sharedBase ** b_secret) % sharedPrime
a_compute = bobSends ** a_secret


print("A sends\t\t", a_send)
print("B computes\t", b_compute)
print("B sends\t\t", bobSends)
print ("A computes\t", a_compute)

print()
print ("Shared Secret ", (sharedBase ** (a_secret * b_secret)) % sharedPrime)