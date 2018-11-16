
# Diffie-Hellman protocol

# Publicly known info
sharedPrime = 23
sharedBase = 5

# Seret information
a_secret = 6
b_secret = 15

# Transmission and Computation
a_send = (sharedBase ** a_secret) % sharedPrime
b_compute = a_send ** b_secret
bobSends = (sharedBase ** b_secret) % sharedPrime
a_compute = bobSends ** a_secret


print("A sends    ", a_send)
print("B computes   ", b_compute)
print("B sends      ", bobSends)
print ("A computes ", a_compute)

print ("Computed Secret ", (sharedBase ** (a_secret * b_secret)) % sharedPrime)