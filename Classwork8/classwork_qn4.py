'''
Exercise 4
For H8, H16, H24, H32 and H40 find a preimage of the corresponding hashes: "\00",
"\00"*2, "\00"*3, "\00"*4, and "\00"*5. Measure how long it takes to find a
preimage.
'''

from Crypto.Hash import SHA512
import time

def collision(null_size):

    print("\nSearching for a preimage of the corresponding hash of '\\00'*%s" % (int(null_size/8)))
    print("...")
    collision = False
    count = 0
    target = b"\x00" * int(null_size/8)

    start = time.time()
    while not collision:
        h = SHA512.new(hex(count).encode())
        digest = h.digest()

        if digest[:int(null_size/8)] == target:
            end = time.time()
            collision = True
            print("Preimage found!")
            print("Preimage: %s" % (count))
            print("Preimage hash: %s" % (digest))
            print("Time taken: %s seconds" % (end - start))

        count += 1

def main():
    collision(8)
    collision(16)
    collision(24)
    collision(32)
    collision(40)

if __name__ == '__main__':
    main()