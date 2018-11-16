'''
Question 3
Let us define a hash function Hn(.) that executes SHA-512 and outputs the n bits.
Find a collision of H8, H16, H24, H32, and H40. Measure how long it takes to find a
collision.
'''

from Crypto.Hash import SHA512
import time

def collision(bit_size):

    print("\nSearching for collision for the first %s bits" % (bit_size))
    print("...")
    collision = False
    count = 0
    hash_array = []

    start = time.time()
    while not collision:
        h = SHA512.new(hex(count).encode())
        #h = SHA512.new(str(count).encode())
        digest = h.hexdigest()[:int(bit_size/4)]
        digest = h.hexdigest()
        #digest = h.digest()

        array_counter = 0
        # Search the digest in the array
        for entry in hash_array:
            if digest[:int(bit_size/4)] == entry[:int(bit_size/4)]:
                end = time.time()
                collision = True
                print("Collision found!")
                print("Message 1: %s" % (array_counter))
                print("Hash: ", entry)
                print("Message 2: %s" % (count))
                print("Hash: ", digest)
                print(
                    "The number %s and %s produces the same SHA512 hash, %s" % (hash_array.index(entry), count, digest))
                print("Time taken: %s seconds" %(end-start))
                break

            array_counter += 1

        hash_array.append(digest)
        count += 1

def main():
    collision(8)
    collision(16)
    collision(24)
    collision(32)
    collision(40)

if __name__ == '__main__':
    main()