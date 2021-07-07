#!/usr/bin/env python3

import pickle
from typing import Union
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aesgenkey(length:int=16):
    "Generate a random sequence of bytes to be used as AES encryption key."
    return get_random_bytes(length)

def aesencrypt(data:Union[str, bytes, dict], key:[str, bytes], typeout:type=dict):
    "Encrypt data with AES encryption key."
    if isinstance(key, str):
        key = open(key,"rb").read()
    if isinstance(data, dict):
        data = pickle.dumps(data)
    if isinstance(data, str):
        with open(data) as fp: data = fp.read()
    cipher = AES.new(key, AES.MODE_EAX)
    cipherdata, tag = cipher.encrypt_and_digest(data)
    cipherpacket = {
        "nonce": cipher.nonce,
        "tag": tag,
        "data": cipherdata
    }
    if typeout == dict:
        return cipherpacket
    elif typeout == bytes:
        return pickle.dumps(cipherpacket)
    else:
        raise Exception(
        "Invalid typeout parameter. Must be either dict or bytes"
        )

def aesdecrypt(cipherdata:Union[str, bytes, dict], key:[str, bytes]):
    "Decrypt data with AES encryption key. Signature is checked via MODE_EAX."
    if isinstance(key, str):
        key = open(key, "rb").read()
    if isinstance(cipherdata, bytes):
        cipherdata = pickle.loads(cipherdata)
    if isinstance(cipherdata, str):
        with open(cipherdata) as fp: cipherdata = fp.read()
    cipher = AES.new(
            key, AES.MODE_EAX,
            cipherdata["nonce"]
    )
    data = cipher.decrypt_and_verify(
            cipherdata["data"],
            cipherdata["tag"]
    )
    return data
