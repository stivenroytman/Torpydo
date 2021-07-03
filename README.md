# Torpydo

## System Dependencies

1. tor
2. pass (optional)

## Usage

Starting a custom tor process:

```python
from Torpydo import tor

conf = {
        'DataDirectory': datadir,
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

process = tor.runtor()

ctrl = tor.getcontrol()

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


