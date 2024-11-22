import argparse
import pathlib
import sys
import os
import base64
import hmac
import hashlib
import struct
import time
import qrcode
import numpy as np
import matplotlib.pyplot as plt
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import qrcode.constants

KEY_DIR = os.path.join(os.getcwd(), 'keydir')

def display_qr_code(img):
    try:
        img_array = np.array(img)
        fig, ax = plt.subplots()
        ax.imshow(img_array, cmap='gray')
        ax.axis('off')
        plt.draw()
        time_val = int(time.time() // 60)
        time2 = int(time.time() // 60)
        while time_val == time2:
            plt.pause(1)
            time2 = int(time.time() // 60)
        ax.text(0.5, 1.05, 'Time is up. Your qr code is not available anymore!', ha='center', va='center', transform=ax.transAxes, fontsize=12, color='red')
        plt.pause(5)
        plt.close()
    except KeyboardInterrupt as e:
        exit('Keyboard Interupt!')

def generate_qr_code(totp_code):
    qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(str(totp_code))
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    display_qr_code(img)


def hotp(secret_key, counter):
    counter_bytes = struct.pack(">Q", counter)
    encoded_secret_key = base64.b32encode(secret_key.encode('utf8'))
    hmac_hash = hmac.new(encoded_secret_key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0xF
    trunc_hash = hmac_hash[offset:offset + 4]
    code = struct.unpack('>I', trunc_hash)[0] & 0x7fffffff
    return code % (10 ** 6)

def generate_totp(otp_key):
   secret_key = decode_otp_key(otp_key)
   time_step = int(time.time() // 60)
   totp_code = hotp(secret_key, time_step)
   print(totp_code)
   generate_qr_code(totp_code)

def decode_otp_key(otp_key):
    try:
        with open(otp_key, 'r') as file:
            encoded_key = file.read()
        encrypted_key = base64.b64decode(encoded_key)
        with open(os.path.join(KEY_DIR, 'priv_key'), 'r') as file:
            priv_key = file.read()
        rsa_object = RSA.importKey(priv_key)
        private_key_object = PKCS1_OAEP.new(rsa_object)
        decrypted_key = private_key_object.decrypt(encrypted_key)
        return (decrypted_key.decode('utf8'))
    except Exception as e:
        exit(f'{e}')

def generate_rsa_encrypt():
    if not os.path.exists(KEY_DIR):
        os.mkdir(KEY_DIR)
    radnom_generator = Random.new().read
    key = RSA.generate(1024, radnom_generator)
    private, public = key.exportKey(), key.publickey().exportKey()
    public_path = os.path.join(KEY_DIR, 'pub_key')
    private_path = os.path.join(KEY_DIR, 'priv_key')
    if not os.path.isfile(public_path):
        with open(public_path, 'w') as public_file:
            public_file.write(public.decode('utf-8'))
        with open(private_path, 'w') as private_file:
            private_file.write(private.decode('utf-8'))
    else:
        with open(public_path, 'r') as file:
            public = file.read().encode('utf8')
    return public



def generate_otp_key(hex_key):
    public_encoder = generate_rsa_encrypt()
    public_key = public_encoder.decode('utf-8')
    rsa_object = RSA.importKey(public_key)
    publick_key_object = PKCS1_OAEP.new(rsa_object)
    ecnrypted_phrase = publick_key_object.encrypt(hex_key.encode('utf8'))
    if not os.path.isfile('ft_otp.key'):
        with open('ft_otp.key', 'w') as file:
            file.write(base64.b64encode(ecnrypted_phrase).decode('utf8'))
            print('Key was succesfully saved in ft_otp.key')
    else:
        exit('ft_otp.key allready exists!')


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
