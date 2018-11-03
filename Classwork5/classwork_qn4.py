import os, random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

password = "1234567890abcdef"
filename = "BLK.bmp"
output_file = "BLK_encrypted.bmp"

def encrypt(key, filename):
    input_file = open(filename, 'rb')
    input_data = input_file.read()
    input_file.close()

    # Pad the input data
    input_data = padding(input_data)
    
    encryptor = AES.new(key, AES.MODE_ECB)
    ciphertext = encryptor.encrypt(input_data)
    print(input_data)
    print(ciphertext)

    encrypted_file = open(output_file, 'wb')
    encrypted_file.write(ciphertext)
    encrypted_file.close()


def padding(data):
    while len(data) % 16 != 0:
        data = data + b'00'
    return data

def aes_encrypt(key, filename):
    chunk_size = 64 * 1024
    encryptor = AES.new(key, AES.MODE_ECB)
    file_size = str(os.path.getsize(filename)).zfill(16)
    with open(filename, 'rb') as inputfile:
        with open(output_file, 'wb') as outf:
            outf.write(file_size)
            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                   chunk += ' '*(16 - len(chunk)%16)
                outf.write(encryptor.encrypt(chunk))
                print(encryptor.encrypt(chunk))


def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def main():
    encrypt(getKey(password), filename)
    # aes_encrypt(getKey(password), filename)
    print("Done!\n%s ==> %s" % (filename, output_file))


if __name__ == "__main__":
    main()