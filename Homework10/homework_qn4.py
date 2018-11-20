'''
Let p = 71, q = 89, n = pq, e = 3. First find the corresponding private RSA key d.
Then compute the signature on m1 = 5416, m2 = 2397, and m3 = m1m2 (mod n)
using the basic RSA operation. Show that the third signature is equivalent to the
product of the first two signatures.
'''

import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

def is_prime(num):
    if num == 2:
         return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')

    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = 3

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e,phi)

    return ((e, n), (d, n))

def sign(d, m):
    return (m ** d[0]) % n


def verify(e, m, c):
    tmp1 = pow(c,e) % n
    tmp2 = m

    if tmp1 == tmp2:
        return True
    else:
        return False

if __name__ == '__main__':

    '''
    Question 4
    '''
    p = 71
    q = 89
    n = p * q
    e = 3

    print("value of n: ", n)

    m1 = 5416
    m2 = 2397
    m3 = (m1 * m2) % n

    public, private = generate_keypair(p,q)

    m1_signed = sign(private, m1)
    m2_signed = sign(private, m2)
    m3_signed = sign(private, m3)

    print("m1_signed: ", m1_signed)
    print("m2_signed: ", m2_signed)
    print("m3_signed: ", m3_signed)

    print()
    print("m1_signed * m2_signed: ", (m1_signed*m2_signed) % n)
    print("m3_signed: ", m3_signed % n)
