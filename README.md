# Torpydo

## System Dependencies

1. tor
2. pass (optional, and not yet fully implemented)

## Installation

```bash
pip install git+https://github.com/stivenroytman/Torpydo
```

For development:

```bash
git clone https://github.com/stivenroytman/Torpydo
cd Torpydo
make
source devel/bin/activate # make sure to run this every time
```

If you are on Windows, you may want to use Windows Subsystem for Linux (WSL) for this. No guarantee that it will work though, I did not test it out.

## Usage

Starting a custom Tor process:

```python
from Torpydo import tor

conf = {
        'DataDirectory': "tordata",
        'HashedControlPassword': tor.torhash(),
        'SocksPort': '9050',
        'ControlPort': '9051',
}

process = tor.runtor(conf)
process.terminate() # to get rid of it once you're done
```

---

Creating a Tor controller object:

```python
from Torpydo import tor

process = tor.runtor() # you will be prompted to create control port password by default

ctrl = tor.getcontrol() # you will be prompted to enter control port password to authenticate

print(ctrl.get_conf("DataDirectory"))
```

---

Creating a hidden service:

```python
from Torpydo import tor

process = tor.runtor()
service = tor.createservice("torapp")
```

---

Removing a hidden service:

```python
from Torpydo import tor

tor.removeservice("torapp")
```

## Disclaimer

Use at your own risk and strictly for educational/legal purposes. No funny business, aight?
