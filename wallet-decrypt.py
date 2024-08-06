#!/usr/bin/env python
from __future__ import print_function

import argparse
import base64
from hashlib import md5
from Crypto.Cipher import AES
import wallet_pb2


# Save as a file
def save_file(text, filename="test.htm"):
    if type(text) != "str":
        text = str(text)
    file = open(filename, "w", encoding="utf-8")
    file.write(text)
    file.close()


# Append as a file
def append_file(text, filename="output.txt"):
    if type(text) != "str":
        text = str(text)
    file = open(filename, "a", encoding="utf-8")
    file.write(text)
    file.close()


# Read file
def read_file(filename="test.htm"):
    file = open(filename, "r", encoding="utf-8")
    text = file.read()
    file.close()
    return text


def derive_key_and_iv(password, salt, key_len, iv_len):
    data = tmp2 = b''
    tmp = password.encode() + salt
    while len(data) < key_len + iv_len:
        msg = tmp2 + tmp
        tmp2 = md5(msg).digest()
        data += tmp2
    key = data[:key_len]
    iv = data[key_len:key_len + iv_len]
    return key, iv


def get_wallet(filename, password):
    with open(filename, 'rb') as f:
        data = base64.b64decode(f.read())
        assert (data[:8] == b'Salted__')
        salt = data[8:16]
        key, iv = derive_key_and_iv(password, salt, 32, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        len(data[AES.block_size:])
        padded_plain = cipher.decrypt(data[AES.block_size:])
        pad_len = padded_plain[-1]

        if isinstance(pad_len, str):
            pad_len = ord(pad_len)

        pbdata = padded_plain[:-pad_len]
        w = wallet_pb2.Wallet()
        w.ParseFromString(pbdata)
        return w


def main(filename, password):
    w = get_wallet(filename, password)
    for k in w.key:
        if len(k.secret_bytes) > 0 and k.type == 3:
            print("\nYou can enter this information in Electrum/Electrum cash\n")
            print('mnemonic       :', k.secret_bytes.decode())
            print("derivation path: m/0'")
            print(password)
            return True
    
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt Bitcon Wallet (Schildbach''s Bitcoin)')
    parser.add_argument('filename')
    parser.add_argument('password')
    args = parser.parse_args()

    with open(args.password, 'r', encoding='utf-8') as file:
        for line in file:
            print(".", end="")
            try:
                if main(args.filename, line.rstrip('\n')) == True:
                    append_file(line, f"{args.filename}.log")
                    break
            except:
                pass
