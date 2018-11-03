'''Question 3
Let us define a hash function Hn(.) that executes SHA-512 and outputs the n bits.
Find a collision of H8, H16, H24, H32, and H40. Measure how long it takes to find a
collision.
'''

from Crypto.Hash import SHA512

# While there is no collision, keep running

collision = False
count = 0
tmp = []

while collision == False:
    h = SHA512.new(hex(count).encode())
    digest = h.digest()
    print(digest.len)

    tmp_counter = 0
    # Search the digest in the array
    for entry in tmp:
        if digest == entry:
            collision = True
            print("\nCollision found!")
            print("Message 1: %s" %(entry))
            print("Message 2: %s" %(digest))
            print("The number %s and %s produces the same SHA512 hash, %s" %(tmp.index(entry), count, digest))
            break


    tmp.append(digest)
    count = count + 1



