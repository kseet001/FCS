import random

p=71
q=89
n=p*q

print("value of n: ",n)
phi=(p-1)*(q-1)
print("value of phi: ",phi)

m1=5416
m2=2397
m3=(m1*m2)%n

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


e = random.randrange(1, phi)

g = gcd(e, phi)
while g != 1:
    e = random.randrange(1, phi)
    g = gcd(e, phi)


print("the value of 'e' is: " ,e ,"and the GCD of e and phi is: " ,gcd(e,phi))


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

d=modinv(e,phi)

print("The value of d is: ", d)

enc = (pow(m3, e)) % n

def sign(d,m):
    return pow(m,d)* n

def verify(e,m,c):
    if ((pow(c,e)%n) == m ):
        print("YES")
        return 1
    else:
        print("NO")
        return 0

signature = sign(enc,d)
print(signature)
print(verify(e,m3,signature))

