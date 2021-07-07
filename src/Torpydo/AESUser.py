#!/usr/bin/env python3

from shutil import rmtree
from .tor import gentorconf, getcontrol, runtor, killtor, createservice, removeservice
from .aes import aesgenkey, aesencrypt, aesdecrypt
import os, pickle

class AESUser:

    def __init__(self,
                 username:str=os.getenv("USER"),
                 keylength:int=16, torconf:dict={}):
        self.username = username
        self.contacts = dict()
        if len(torconf) == 0: torconf = gentorconf()
        self.torconf = torconf
        self.torstack = list()
        self.servicetable = dict()

    def addcontact(self, username:str, key:bytes):
        if username in self.contacts.keys():
            if self.contacts[username] != key:
                print("[WARN]: inconsitent entry.")
                return None
            else:
                print("[WARN]: duplicate entry.")
        else:
            print(f"[LOG]: new contact entry -> {username}[{hash(key)}]")
            self.contacts[username] = key

    def serialize(self, keypath:str="", force=False):
        if len(self.torstack) > 0:
            if not force:
                raise Exception("Tor processes are still running. Run killtor() or set force to True.")
            else:
                killtor()
        pickleself = pickle.dumps(self)
        if len(keypath) == 0: return pickleself
        with open(keypath, "rb") as fp: aeskey = fp.read()
        cryptself = aesencrypt(pickleself, aeskey, bytes)
        return cryptself

    def runtor(self, torconf:dict={}, torcmd:str="tor", force:bool=False):
        if len(torconf) == 0: torconf = self.torconf
        try:
            self.torstack.append(runtor(torconf, torcmd))
        except OSError:
            if not force:
                raise OSError("Cannot bind port. Run killtor() or set force to True.")
            else:
                killtor()
                self.torstack.append(runtor(torconf, torcmd))

    def killtor(self, nuke:bool=True):
        for tor in self.torstack:
            torproc = self.torstack.pop()
            torproc.kill()
            torproc.kill()
        if nuke: killtor()


    def createservice(self, name:str="", torport:int=80, localport:int=5000):
        if len(name) == 0:
            name = self.username + ".tordir"
        else:
            name = name + ".tordir"
        service = createservice(name, torport, localport, self.torconf["ControlPort"])
        self.servicetable[name.split(".")[0]] = service

    def removeservice(self, name:str=""):
        if len(name) == 0: name = self.username
        if name in self.servicetable.keys():
            removeservice(self.servicetable.pop(name), self.torconf["ControlPort"])
        else:
            raise Exception("Service does not exist.")

    def nuke(self):
        rmtree(self.torconf["DataDirectory"])

def saveuser(user:AESUser, aeskey:bytes=b"", userpath:str="", keypath:str=""):
    if len(aeskey) == 0: aeskey = aesgenkey()
    if len(userpath) == 0: userpath = f"{user.username}.bin"
    if len(keypath) == 0: keypath = f"{user.username}_key.bin"
    with open(keypath, "wb") as fp: fp.write(aeskey)
    userbytes = user.serialize(keypath)
    with open(userpath, "wb") as fp: fp.write(userbytes)

def loaduser(userpath:str, keypath:str):
    with open(userpath, "rb") as fp: userbytes = fp.read()
    with open(keypath, "rb") as fp: keybytes = fp.read()
    cryptuser = pickle.loads(userbytes)
    pickleuser = aesdecrypt(cryptuser, keybytes)
    return pickle.loads(pickleuser)
