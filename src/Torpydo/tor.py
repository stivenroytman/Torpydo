#!/usr/bin/env python3

import os, socks, pickle
import subprocess as sp
import requests as req
from psutil import process_iter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Union
from shutil import rmtree, which
from getpass import getpass
from stem.control import Controller, CreateHiddenServiceOutput
from stem.process import launch_tor_with_config
from stem import Signal

def torhash(check:bool=True) -> str:
    "Generate hashed password for Tor control port."
    first = getpass()
    if check:
        second = getpass("Please enter password again: ")
        if first != second: raise Exception("Passwords don't match. Please try again.")
    pwdhash = sp.check_output(["tor", "--hash-password", first])
    return pwdhash.strip().decode()

def gentorconf(
        datadir:str=os.path.join(os.getenv("HOME"),".tordata"),
        sockport:int=9050, cport:Union[str, int]="9051"
    ) -> dict:
    "Generate configuration for custom Tor process."
    if not os.path.isdir(datadir): os.mkdir(datadir)
    return {
        'DataDirectory': datadir,
        'HashedControlPassword': torhash(),
        'SocksPort': str(sockport),
        'ControlPort': str(cport)
    }

def runtor(config:dict={}, torcmd:str="tor") -> sp.Popen:
    "Run Tor process."
    if len(config) == 0:
        config = gentorconf()
    return launch_tor_with_config(config, torcmd)

def getcontrol(cport:Union[str, int]=9051, passptr:str="") -> Controller:
    "Authenticate with Tor controller."
    controller = Controller.from_port(port=int(cport))
    if passptr != "" and which("pass") != "":
        password = sp.check_output(["pass", passptr]).strip().decode()
    else:
        password = getpass()
    controller.authenticate(password)
    return controller

def createservice(
        name:str, 
        torport:int=80, 
        localport:int=5000, 
        cport:Union[str, int]=9051
    ) -> CreateHiddenServiceOutput:
    "Create and/or start Tor hidden service."
    with getcontrol(int(cport)) as ctrl:
        datadir = ctrl.get_conf("DataDirectory")
        appdir = os.path.join(datadir, name)
        service = ctrl.create_hidden_service(appdir, torport, target_port=localport)
    return service

def removeservice(
        service:Union[str,CreateHiddenServiceOutput], 
        cport:Union[str, int]=9051, clean:bool=True, nuke:bool=False
    ):
    "Stop Tor hidden service, optionally deleting service directory and/or Tor DataDirectory."
    with getcontrol(int(cport)) as ctrl:
        if isinstance(service, str):
            datadir = ctrl.get_conf("DataDirectory")
            appdir = os.path.join(datadir, service)
        else:
            appdir = service.path
            datadir = os.path.split(appdir)[0]
        ctrl.remove_hidden_service(appdir)
        if clean:
            rmtree(appdir)
        if nuke:
            rmtree(datadir)

def torget(
        hostname:str, 
        hostport:Union[str, int]="80", 
        onionport:Union[str, int]="9050"
    ):
    "Perform GET request via Tor at given hostname."
    return req.get(
        f"{hostname}:{hostport}",
        proxies={
            "http":f"socks5h://127.0.0.1:{onionport}",
            "https":f"socks5h://127.0.0.1:{onionport}"
        }
    )

def torpost(
        hostname:str, payload:dict, 
        hostport:Union[str, int]="80", 
        onionport:Union[str, int]="9050"
    ):
    "Perform POST request via Tor at given hostname with given payload."
    return req.post(
        f"{hostname}:{hostport}",
        json=payload,
        proxies={
            "http":f"socks5h://127.0.0.1:{onionport}",
            "https":f"socks5h://127.0.0.1:{onionport}"
        }
    )

def iprefresh(cport:Union[str, int]=9051):
    "Change Tor IP address by communicating to Tor controller."
    with getcontrol(int(cport)) as ctrl:
        ctrl.signal(Signal.NEWNYM)

def torsock(
        hostname:str, 
        hostport:Union[str, int]="80",
        onionport:Union[str, int]="9050"
    ):
    "Connects to a TCP socket on given .onion url (hostname), with given hostport."
    oSocket = socks.socksocket()
    oSocket.set_proxy(socks.SOCKS5, 'localhost', int(onionport))
    oSocket.connect((hostname, int(hostport)))
    return oSocket

def aesgenkey(length:int=16):
    "Generate a random sequence of bytes to be used as AES encryption key."
    return get_random_bytes(length)

def aesencrypt(data:Union[bytes, dict], key:[str, bytes], typeout:type=dict):
    "Encrypt data with AES encryption key."
    if isinstance(key, str):
        key = open(key,"rb").read()
    if isinstance(data, dict):
        data = pickle.dumps(data)
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

def aesdecrypt(cipherdata:Union[bytes, dict], key:[str, bytes]):
    "Decrypt data with AES encryption key. Signature is checked via MODE_EAX."
    if isinstance(key, str):
        key = open(key, "rb").read()
    if isinstance(cipherdata, bytes):
        cipherdata = pickle.loads(cipherdata)
    cipher = AES.new(
            key, AES.MODE_EAX, 
            cipherdata["nonce"]
    )
    data = cipher.decrypt_and_verify(
            cipherdata["data"],
            cipherdata["tag"]
    )
    return data

def lstor():
    "List all running Tor processes."
    return list(
        filter(
            lambda proc: proc.name() == "tor",
            process_iter()
        )
    )

def killtor():
    "Kill all running Tor processes."
    list(
        map(
            lambda tor: tor.kill(),
            filter(
                lambda proc: proc.name() == "tor",
                process_iter()
            )
        )
    )

class User:

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

def saveuser(user:User, aeskey:bytes=b"", userpath:str="", keypath:str=""):
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
