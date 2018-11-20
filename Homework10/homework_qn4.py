import random



def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

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
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)
    print("Phi: ", phi)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e,phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = pow(int(plaintext),key) % n#[(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher

def sign(d,m):
    key, n = d
    return pow(m,key)* n

def verify(e,m,c):
    if ((pow(c,e)%n) == m ):
        print("YES")
        return 1
    else:
        print("NO")
        return 0

if __name__ == '__main__':
    p = 71
    q = 89

    m1 = 5416
    m2 = 2397


    public, private = generate_keypair(p, q)
    print("Your public key is ", public, " and your private key is ", private)
    m3 = (m1 * m2) % public[1]
    print("m3: ",m3)
    print("Signed Message = ", sign(private,encrypt(public,m3)))


