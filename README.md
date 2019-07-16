![](http://media.charlesleifer.com/blog/photos/logo-1.png)

Fast bindings to kyototycoon.

* Full-featured implementation of protocol.
* Simple APIs.
* Thread-safe and greenlet-safe.
* Additional serializers implemented as a C extension.

View the [documentation](http://ukt.readthedocs.io/en/latest/) for more info.

#### installing

```console

$ pip install ukt
```

#### usage

```pycon

>>> from ukt import KyotoTycoon
>>> client = KyotoTycoon()
>>> client.set('k1', 'v1')
1
>>> client.get('k1')
'v1'
>>> client.remove('k1')
1

>>> client.set_bulk({'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})
3
>>> client.get_bulk(['k1', 'xx, 'k3'])
{'k1': 'v1', 'k3': 'v3'}
>>> client.remove_bulk(['k1', 'xx', 'k3'])
2
```
