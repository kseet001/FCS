
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
b_sends = (sharedBase ** b_secret) % sharedPrime

print("A sends\t\t", a_send)
print("B sends\t\t", b_sends)

print()
print("Shared Secret ", (sharedBase ** a_secret) ** b_secret % sharedPrime)
