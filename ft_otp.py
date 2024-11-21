import argparse
import pathlib
import sys
import os
from Crypto import Random
from Crypto.PublicKey import RSA

KEY_DIR = os.path.join(os.getcwd(), 'keydir')

def generate_totp(hex_key):
    print('YES BABY YES')

def generate_rsa_encrypt():
    if not os.path.exists(KEY_DIR):
        os.mkdir(KEY_DIR)
    radnom_generator = Random.new().read
    key = RSA.generate(1024, radnom_generator)
    private, public = key.exportKey(), key.publickey().exportKey()
    public_path = os.path.join(KEY_DIR, 'pub_key')
    private_path = os.path.join(KEY_DIR, 'priv_key')
    if not os.path.isfile(public_path) and not os.path.isfile(private_path):
        with open(public_path, 'w') as public_file:
            public_file.write(public.decode('utf-8'))
        with open(private_path, 'w') as private_file:
            private_file.write(private.decode('utf-8'))



def generate_otp_key(hex_key):
    generate_rsa_encrypt()

def check_hexkey(hex_key):
    try:
        with open(hex_key, 'r') as file:
            file_content = file.read()
            if len(file_content) < 64:
                raise Exception('Your hex_key has to be at least 64 charachter long!')
            for char in file_content:
                if char not in '0123456789abcdefABCDEF':
                    raise Exception(f'Your hex_key can only contain hexadecimal characters {char}!')
            return file_content
    except Exception as e:
        print(f'{e}')
        exit ()

def main():
    parser = argparse.ArgumentParser(description='TOTP encryption method')
    parser.add_argument('-g', type=pathlib.Path, help='path to hexadecimal key')
    parser.add_argument('-k', type=pathlib.Path, help='path to key file to generate a new temporary password')
    args = parser.parse_args()
    if len(sys.argv) != 3:
        parser.error('One argument required!')
    if args.g is not None:
        hex_key = check_hexkey(args.g)
        generate_otp_key(hex_key)
    elif args.k is not None:
        generate_totp(args.k)


if __name__=='__main__':
    main()
