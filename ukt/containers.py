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

    def set_bulk(self, __data=None, **kwargs):
        if __data is not None:
            kwargs.update(__data)
        out = self.lua('hmset', kwargs, decode=False)
        return int(out[b'num'])

    def get_bulk(self, keys):
        return self.lua('hmget', {key: '' for key in keys})

    def remove_bulk(self, keys):
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
        out = self.lua('hget', raw_data={'key': key})
        if out:
            return out['value']

    def remove(self, key):
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
    __delitem__ = remove
    update = set_bulk


class Set(Container):
    key_field = 'key'

    def add(self, *values):
        return self.add_bulk(values)

    def add_bulk(self, values):
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

    def remove(self, *values):
        return self.remove_bulk(values)

    def remove_bulk(self, values):
        out = self.lua('srem', {str(i): v for i, v in enumerate(values)},
                       decode=False)
        return int(out[b'num'])

    __contains__ = contains
    __delitem__ = remove
    __len__ = count


class List(Container):
    key_field = 'key'

    def appendleft(self, value):
        return int(self.lua('llpush', {'value': value}, False)[b'length'])

    def append(self, value):
        return int(self.lua('lrpush', {'value': value}, False)[b'length'])
    appendright = append

    def extend(self, values):
        out = self.lua('lextend', {str(i): v for i, v in enumerate(values)},
                       decode=False)
        return int(out[b'length'])

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
        out = self.lua('linsert', {'value': value}, decode=False,
                       raw_data={'index': index})
        return int(out[b'length'])

    def remove(self, index):
        out = self.lua('lrem', decode=True, raw_data={'index': str(index)})
        return out.get('value')

    def remove_range(self, start=None, stop=None):
        data = {}
        if start is not None: data['start'] = str(start)
        if stop is not None: data['stop'] = str(stop)
        out = self.lua('lremrange', decode=False, raw_data=data)
        return int(out[b'length'])

    def popleft(self):
        out = self.lua('llpop', decode=True)
        if out:
            return out['value']

    def popright(self):
        out = self.lua('lrpop', decode=True)
        if out:
            return out['value']

    def pop(self, index=None):
        return self.remove(index) if index is not None else self.popright()

    def length(self):
        out = self.lua('llen', decode=False)
        return int(out[b'num'])

    def set(self, index, value):
        self.lua('lset', {'value': value}, decode=True,
                 raw_data={'index': index})

    def find(self, value):
        out = self.lua('lfind', {'value': value}, decode=False)
        idx = int(out[b'index'])
        return idx if idx >= 0 else None

    def rfind(self, value):
        out = self.lua('lrfind', {'value': value}, decode=False)
        idx = int(out[b'index'])
        return idx if idx >= 0 else None

    def __getitem__(self, item):
        if isinstance(item, slice):
            return self.get_range(item.start, item.stop)
        return self.index(item)

    __setitem__ = set
    __delitem__ = remove
    __len__ = length

    def __contains__(self, value):
        return self.find(value) is not None