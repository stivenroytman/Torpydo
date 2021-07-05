#!/usr/bin/env python3

import os, socks
import subprocess as sp
import requests as req
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
        sockport:int=9050, cport:int=9051
    ) -> dict:
    "Generate configuration for custom Tor process."
    if not os.path.isdir(datadir): os.mkdir(datadir)
    return {
        'DataDirectory': datadir,
        'HashedControlPassword': torhash(),
        'SocksPort': str(sockport),
        'ControlPort': str(cport),
        'Log': [
            'NOTICE syslog',
            'ERR file /tmp/tor_error_log'
        ]
    }

def runtor(config:dict={}, torcmd:str="tor") -> sp.Popen:
    "Run Tor process."
    if len(config) == 0:
        config = gentorconf()
    return launch_tor_with_config(config, torcmd)

def getcontrol(cport:int=9051, passptr:str="") -> Controller:
    "Authenticate with Tor controller."
    controller = Controller.from_port(port=cport)
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
        cport:int=9051
    ) -> CreateHiddenServiceOutput:
    "Create and/or start Tor hidden service."
    with getcontrol(cport) as ctrl:
        datadir = ctrl.get_conf("DataDirectory")
        appdir = os.path.join(datadir, name)
        service = ctrl.create_hidden_service(appdir, torport, target_port=localport)
    return service

def removeservice(
        service:Union[str,CreateHiddenServiceOutput], 
        cport:int=9051, clean:bool=True, nuke:bool=False
    ):
    "Stop Tor hidden service, optionally deleting service directory and/or Tor DataDirectory."
    with getcontrol(cport) as ctrl:
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

def iprefresh(cport:int=9051):
    "Change Tor IP address by communicating to Tor controller."
    with getcontrol(cport) as ctrl:
        ctrl.signal(Signal.NEWNYM)

def torsock(
        hostname:str, 
        hostport:Union[str, int]="80",
        onionport:Union[str, int]="9050"
    ):
    oSocket = socks.socksocket()
    oSocket.set_proxy(socks.SOCKS5, 'localhost', int(onionport))
    oSocket.connect((hostname, int(hostport)))
    return oSocket


