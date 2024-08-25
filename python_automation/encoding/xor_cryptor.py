import sys

XOR_KEY = b"simplexor"

def xor(input_data, encryption_key):
    result = bytearray()
    for i in range(len(input_data)):
        result.append(input_data[i] ^ encryption_key[i % len(encryption_key)])
    return bytes(result)

def formatHex(ciphertext):
    #print('{', end=' ')
    for i, byte in enumerate(ciphertext):
        if i == len(ciphertext) - 1:
            print(f'0x{byte:02x}', end='')
        else:
            print(f'0x{byte:02x},', end=' ')
    #print('};')

def main():
    try:
        plaintext = open(sys.argv[1],"rb").read()
    except:
        print("Usage: C:\Python27\python.exe xor_cryptor.py BIN_FILE > OUTPUT_FILE")
        print("Usage: python3 xor_cryptor.py BIN_FILE > OUTPUT_FILE")
        sys.exit()
    encoded_data = xor(plaintext, XOR_KEY)
    #print(encoded_data.hex())
    formatHex(encoded_data)

if __name__ == '__main__':
    main()