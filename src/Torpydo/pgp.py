#!/usr/bin/env python3

import os, pgpy, pickle
from typing import Union
from pgpy.pgp import PGPKey, PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from getpass import getpass

def genkey(name:str=os.getenv("USER"), keylength:int=4096, protected:bool=True) -> PGPKey:
    key = PGPKey.new(
            PubKeyAlgorithm.RSAEncryptOrSign,
            keylength
    )
    uid = pgpy.PGPUID.new(name)
    key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed]
    )
    first = getpass("New private key password: ")
    second = getpass("Enter password for verification: ")
    if first != second:
        raise Exception("Password entries don't match. Please try again.")
    del second
    if protected:
        key.protect(first, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        return key
    del first
    return key

def newmsg(data:Union[str, bytes, dict]) -> PGPMessage:
    if isinstance(data, str):
        msg = PGPMessage.new(data, file=True)
    elif isinstance(data, bytes):
        msg = PGPMessage.new(data)
    elif isinstance(data, dict):
        msg = PGPMessage.new(pickle.dumps(data))
    return msg

def signmsg(msg:PGPMessage, key:PGPKey):
    with key.unlock(getpass()) as privkey:
        msg |= privkey.sign(msg)

def savekey(key:PGPKey, path:str, binary:bool=False):
    if binary:
        keydata = bytes(key)
        opentype = "wb"
    else:
        keydata = str(key)
        opentype = "w"
    with open(path, opentype) as fp:
        fp.write(keydata)

def loadkey(key:Union[str, bytes]) -> PGPKey:
    if isinstance(key, str):
        return PGPKey.from_file(key)[0]
    elif isinstance(key, bytes):
        return PGPKey.from_blob(key)[0]
