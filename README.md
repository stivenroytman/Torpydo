# Torpydo

## System Dependencies

1. tor
2. pass (optional, and not yet fully implemented)

## Installation

```bash
pip install git+https://github.com/stivenroytman/Torpydo
```

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
