class Container(object):
    key_field = None

    def __init__(self, kt, key, encode_values=True, decode_values=True):
        self.kt = kt
        self.key = key
        self.encode_values = encode_values
        self.decode_values = decode_values

    def lua(self, func, data=None, decode=None, raw_data=None):
        # We need to pass the container key, e.g. "table_key", without any
        # special serialization. Everything else may be serialized using the
        # configured serializer, however.
        accum = {self.key_field: self.key}
        if raw_data:
            accum.update(raw_data)

        if data:
            if self.encode_values:
                for key, value in data.items():
                    accum[key] = self.kt.encode_value(value)
            else:
                accum.update(data)

        decode_vals = self.decode_values if decode is None else decode
        return self.kt.script(func, accum, encode_values=False,
                              decode_values=decode_vals, _decode_keys=decode)


class Hash(Container):
    key_field = 'table_key'

    def mset(self, __data=None, **kwargs):
        if __data is not None:
            kwargs.update(__data)
        out = self.lua('hmset', kwargs, decode=False)
        return int(out[b'num'])

    def mget(self, keys):
        return self.lua('hmget', {key: '' for key in keys})

    def mdelete(self, keys):
        out = self.lua('hmdel', {key: '' for key in keys}, decode=False)
        return int(out[b'num'])

    def get_all(self):
        return self.lua('hgetall')

    def set(self, key, value):
        out = self.lua('hset', {'value': value}, False, {'key': key})
        return int(out[b'num'])

    def setnx(self, key, value):
        out = self.lua('hsetnx', {'value': value}, False, {'key': key})
        return int(out[b'num'])

    def get(self, key):
        return self.lua('hget', raw_data={'key': key})['value']

    def delete(self, key):
        out = self.lua('hdel', decode=False, raw_data={'key': key})
        return int(out[b'num'])

    def length(self):
        return int(self.lua('hlen', decode=False)[b'num'])

    def contains(self, key):
        out = self.lua('hcontains', decode=False, raw_data={'key': key})
        return int(out[b'num'])

    __len__ = length
    __contains__ = contains
    __getitem__ = get
    __setitem__ = set
    __delitem__ = delete
    update = mset


class Set(Container):
    key_field = 'key'

    def add(self, *values):
        return self.madd(values)

    def madd(self, values):
        out = self.lua('sadd', {str(i): v for i, v in enumerate(values)},
                       decode=False)
        return int(out[b'num'])

    def count(self):
        return int(self.lua('scard', decode=False)[b'num'])

    def contains(self, value):
        out = self.lua('sismember', {'value': value}, decode=False)
        return int(out[b'num'])

    def members(self):
        out = self.lua('smembers')
        return set(out.values())

    def pop(self):
        out = self.lua('spop', decode=False)
        if out[b'num'] == b'1':
            value = out[b'value']
            if self.decode_values:
                value = self.kt.decode_value(value)
            return value

    def delete(self, value):
        out = self.lua('srem', {'value': value}, decode=False)
        return int(out[b'num'])

    __contains__ = contains
    __len__ = count


class List(Container):
    key_field = 'key'

    def appendleft(self, value):
        self.lua('llpush', {'value': value})

    def append(self, value):
        self.lua('lrpush', {'value': value})
    appendright = append

    def get_range(self, start=None, stop=None):
        kwargs = {}
        if start is not None: kwargs['start'] = start
        if stop is not None: kwargs['stop'] = stop
        out = self.lua('lrange', decode=True, raw_data=kwargs)
        accum = []
        for i in range(len(out)):
            accum.append(out[str(i)])
        return accum

    def index(self, index):
        out = self.lua('lindex', decode=True, raw_data={'index': index})
        if out:
            return out['value']

    def insert(self, index, value):
        self.lua('linsert', {'value': value}, decode=True,
                 raw_data={'index': index})

    def popleft(self):
        out = self.lua('llpop', decode=True)
        if out:
            return out['value']

    def pop(self):
        out = self.lua('lrpop', decode=True)
        if out:
            return out['value']
    popright = pop

    def length(self):
        out = self.lua('llen', decode=False)
        return int(out[b'num'])

    def set(self, index, value):
        self.lua('lset', {'value': value}, decode=True,
                 raw_data={'index': index})

    def __getitem__(self, item):
        if isinstance(item, slice):
            return self.get_range(item.start, item.stop)
        return self.index(item)

    __setitem__ = set
    __len__ = length
