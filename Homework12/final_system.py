import PKI
import secure_channel
from Crypto.PublicKey import RSA
import random
from Crypto.Hash import SHA, SHA256
from Crypto.Signature import PKCS1_PSS as PKCS2
import math

print("\nGenerating RSA keys for Root CA, Alice and Bob...")
root_key = RSA.generate(2048)
alice_key = RSA.generate(2048)
bob_key = RSA.generate(2048)

alice = PKI.Person("Alice")
bob = PKI.Person("Bob")
root_ca = PKI.CA("root", root_key)

def main():
    print("==================== Generating certificates from CA ====================\n")
    alice_cert = root_ca.create_certificate("alice", alice_key.publickey())
    bob_cert = root_ca.create_certificate("bob", bob_key.publickey())

    print("Alice's certificate:\n", alice_cert)
    print("\nBob's certificate:\n", bob_cert)

    # Alice sends Bob her Certificate
    issuer_key = root_ca.get_public_key()
    bob.verify_cert(alice_cert, issuer_key)

    print("\n==================== Certificates generation completed ====================\n")

    print("\n==================== Starting key negotiation ====================\n")
    # Key negotiation
    session_key = modified_key_negotiation(alice_key, bob_key, alice_cert, bob_cert)

    print("\nGenerated session key: ", session_key)
    print("\n==================== Key negotiation ended ====================\n")

    print("\n==================== Establishing secure channel ====================\n")
    # Creating two secure channel peers (Alice and Bob)
    secure_alice = secure_channel.Peer(session_key, "Alice")
    secure_bob = secure_channel.Peer(session_key, "Bob")

    print("Alice encrypts the message 'Hello Bob' and sends:")
    msg1 = secure_alice.send("Hello Bob")
    print(msg1)

    print("\nBob decrypts the message and reads:")
    decrypted_msg1 = secure_bob.receive(msg1)
    print(decrypted_msg1)

    print("\nBob encrypts the message 'Goodbye Alice' and sends:")
    msg2 = secure_bob.send("Goodbye Alice")
    print(msg2)

    print("\nAlice decrypts the message and reads:")
    decrypted_msg2 = secure_alice.receive(msg2)
    print(decrypted_msg2)

    print("\n==================== End ====================\n")

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


def modified_key_negotiation(key_A, key_B, cert_A, cert_B):
    # Alice
    S_alice = 3  # min prime size = 3
    N = random.randint(0, (2 ** 256) - 1)
    print("Alice sends {S_alice: %s, N: %s, certificate: %s" % (S_alice, N, cert_A))
    print()

    # Bob verifies Alice's certificate first, before going thru the key negotiation process
    if bob.verify_cert(cert_A, root_ca.get_public_key()):
        S_bob = 3
        s = max(S_alice, S_bob)
        assert s <= 2 * S_bob
        # Bob Chooses (g,p,q)
        q = 5
        p = 2 * q + 1
        alpha = random.randint(2, p - 2)
        g = alpha ** 2 % p
        # assert
        assert g != 1
        assert g != (p - 1)
        b = random.randint(1, q - 1)
        B = g ** b % p

        s_str = str(N)

        # Bob sends
        h = SHA.new(s_str.encode())
        signer = PKCS2.new(key_B)
        signature = signer.sign(h)
        print("Bob sends: {(g,p,q): (%s,%s,%s), B: %s, AUTHbob: %s, Bob's Certificate: %s" % (g, p, q, B, signature, cert_B))
        print()
    else:
        print("Key negotiation failed")
        return

    # Alice receives
    h = SHA.new(s_str.encode())
    verifier = PKCS2.new(key_B)
    # Alice checks AUTHbob and the Bob's certificate
    if (verifier.verify(h, signature)) and (alice.verify_cert(cert_B, root_ca.get_public_key())):
        # Assert
        assert (S_alice - 1) <= math.log(p, 2)
        assert math.log(p, 2) <= 2 * S_alice
        assert 2 <= math.log(q, 2) <= 3
        assert p == is_prime(p)
        assert q == is_prime(q)
        assert q | (p - 1) ^ g != 1 ^ (g ** q == 1)
        assert B != 1 ^ (B ** q != 1)
        a = random.randint(1, q - 1)
        A = g ** a % p

        h = SHA.new(s_str.encode())
        signer = PKCS2.new(key_A)
        signature = signer.sign(h)
        Kp = (B ** a) % p
        alice_K = SHA256.new(str(Kp).encode()).hexdigest()
        #print("Alice sends: A=", A, " AUTHalice=", signature)
        print("Alice sends: {A: %s, AUTHalice: %s" % (A, signature))
        print()
    else:
        print("key negotiation failed")
        return

    # Send to Bob
    h = SHA.new(s_str.encode())
    verifier = PKCS2.new(key_A)

    # Bob checks AUTHalice
    if verifier.verify(h, signature):
        #print("Alice's signature is valid")
        assert A != 1
        assert A ** q % p == 1

        Kp2 = (A ** b) % p
        bob_K = SHA256.new(str(Kp2).encode()).hexdigest()
        return alice_K

    else:
        print("Key negotiation failed.")
        return

if __name__ == '__main__':
    main()
