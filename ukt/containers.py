class Container(object):
    """
    Container-types that emulate Python containers.

    These container types rely on Lua functions in scripts/kt.lua.

    Behind-the-scenes these types rely on KT's internal mapload/mapdump and
    arrayload/arraydump functionality. For reading and writing the binary
    representation of the container types, you can use:

    * :py:meth:`KyotoTycoon.serialize_dict` for mapdump
    * :py:meth:`KyotoTycoon.deserialize_dict` for mapload
    * :py:meth:`KyotoTycoon.serialize_list` for arraydump
    * :py:meth:`KyotoTycoon.deserialize_list` for arrayload

    Because the full data must be deserialized for reading, and serialized when
    writing back any changes, all operations are O(n).
    """
    key_field = None

    def __init__(self, kt, key, encode_values=True, decode_values=True,
                 db=None):
        self.kt = kt
        self.key = key
        self.encode_values = encode_values
        self.decode_values = decode_values
        self.db = db

    def lua(self, func, data=None, decode=None, raw_data=None):
        # We need to pass the container key, e.g. "table_key", without any
        # special serialization. Everything else may be serialized using the
        # configured serializer, however.
        db = self.db if self.db is not None else self.kt.default_db
        accum = {self.key_field: self.key, 'db': db}
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

    def clear(self):
        self.kt.remove(self.key)


class Hash(Container):
    """
    Container-type to emulate a Python dictionary stored in a single key.
    """
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

    def unpack(self, prefix=None):
        data = {} if prefix is None else {'prefix': prefix}
        out = self.lua('hunpack', decode=False, raw_data=data)
        return int(out[b'num'])

    def pack(self, start=None, stop=None, count=None):
        data = {}
        if start is not None: data['start'] = start
        if stop is not None: data['stop'] = stop
        if count is not None: data['count'] = str(count)
        out = self.lua('hpack', decode=False, raw_data=data)
        return int(out[b'num'])

    def pack_keys(self, key):
        # Note that keys are *not* serialized in hashes, so if you are using
        # a serialization like json/pickle/msgpack, the keys will be unreadable
        # using the List container functionality, which expects list items to
        # be serialized.
        out = self.lua('hpackkeys', decode=False, raw_data={'key': key})
        return int(out[b'num'])

    def pack_values(self, key):
        out = self.lua('hpackvalues', decode=False, raw_data={'key': key})
        return int(out[b'num'])

    __len__ = length
    __contains__ = contains
    __getitem__ = get
    __setitem__ = set
    __delitem__ = remove
    update = set_bulk

    def get_raw(self):
        # Extract the dictionary directly from KT and deserialize manually.
        raw_data = self.kt.get_bytes(self.key, db=self.db)
        if raw_data is not None:
            return self.kt.deserialize_dict(raw_data, self.decode_values)
    def set_raw(self, d):
        data = self.kt.serialize_dict(d, self.encode_values)
        return self.kt.set_bytes(self.key, data, db=self.db)


class Set(Container):
    """
    Container-type to emulate a Python set stored in a single key.
    """
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

    def _multi_store(self, fn, other, dest=None):
        raw_data = {'key2': other.key if isinstance(other, Set) else other}
        if dest is not None:
            raw_data['dest'] = dest.key if isinstance(other, Set) else dest
        out = self.lua(fn, decode=True, raw_data=raw_data)
        return set(out.values())

    def intersection(self, other, dest=None):
        return self._multi_store('sinter', other, dest)

    def union(self, other, dest=None):
        return self._multi_store('sunion', other, dest)

    def difference(self, other, dest=None):
        return self._multi_store('sdiff', other, dest)

    __contains__ = contains
    __delitem__ = remove
    __len__ = count
    __and__ = intersection
    __or__ = union
    __sub__ = difference


class List(Container):
    """
    Container-type to emulate a Python list stored in a single key.
    """
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
        if not out:
            raise IndexError('invalid index for list "%s"' % self.key)
        return out['value']

    def insert(self, index, value):
        out = self.lua('linsert', {'value': value}, decode=False,
                       raw_data={'index': index})
        if not out:
            raise IndexError('invalid index for list "%s"' % self.key)
        return int(out[b'length'])

    def remove(self, index):
        out = self.lua('lrem', decode=True, raw_data={'index': str(index)})
        if not out:
            raise IndexError('invalid index for list "%s"' % self.key)
        return out['value']

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
        if index is not None:
            try:
                return self.remove(index)
            except IndexError:
                pass
        else:
            return self.popright()

    def _poppush(self, cmd, dest):
        if dest is None:
            dest = self.key
        elif isinstance(dest, List):
            dest = dest.key
        out = self.lua(cmd, raw_data={'dest': dest}, decode=True)
        try:
            return out['value']
        except KeyError:
            raise IndexError('no data in source')

    def lpoprpush(self, dest=None):
        return self._poppush('llpoprpush', dest)

    def rpoplpush(self, dest=None):
        return self._poppush('lrpoplpush', dest)

    def length(self):
        out = self.lua('llen', decode=False)
        return int(out[b'num'])

    def set(self, index, value):
        out = self.lua('lset', {'value': value}, decode=False,
                       raw_data={'index': index})
        if not out:
            raise IndexError('invalid index for list set()')

    def find(self, value):
        out = self.lua('lfind', {'value': value}, decode=False)
        idx = int(out[b'index'])
        return idx if idx >= 0 else None

    def rfind(self, value):
        out = self.lua('lrfind', {'value': value}, decode=False)
        idx = int(out[b'index'])
        return idx if idx >= 0 else None

    def unpack(self, start=None, stop=None, prefix=None, fmt=None):
        data = {}
        if start is not None: data['start'] = str(start)
        if stop is not None: data['stop'] = str(stop)
        if prefix is not None: data['prefix'] = prefix
        if fmt is not None: data['format'] = fmt
        out = self.lua('lunpack', decode=False, raw_data=data)
        return int(out[b'num'])

    def pack(self, start=None, stop=None, count=None):
        data = {}
        if start is not None: data['start'] = start
        if stop is not None: data['stop'] = stop
        if count is not None: data['count'] = str(count)
        out = self.lua('lpack', decode=False, raw_data=data)
        return int(out[b'num'])

    def __getitem__(self, item):
        if isinstance(item, slice):
            return self.get_range(item.start, item.stop)
        return self.index(item)

    __setitem__ = set
    __delitem__ = remove
    __len__ = length

    def __contains__(self, value):
        return self.find(value) is not None

    def get_raw(self):
        raw_data = self.kt.get_bytes(self.key, db=self.db)
        if raw_data is not None:
            return self.kt.deserialize_list(raw_data, self.decode_values)
    def set_raw(self, l):
        data = self.kt.serialize_list(l, self.encode_values)
        return self.kt.set_bytes(self.key, data, db=self.db)
