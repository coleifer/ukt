from base64 import b64decode
from base64 import b64encode
from contextlib import contextmanager
from functools import partial
try:
    from http.client import HTTPConnection
    from urllib.parse import quote_from_bytes
    from urllib.parse import unquote_to_bytes
    from urllib.parse import urlencode
except ImportError:
    from httplib import HTTPConnection
    from urllib import quote as quote_from_bytes
    from urllib import unquote as unquote_to_bytes
    from urllib import urlencode
import datetime
import heapq
import io
import itertools
import json
import re
import socket
import struct
import sys
import threading
import time

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    import msgpack
except ImportError:
    msgpack = None


if sys.version_info[0] > 2:
    unicode = str


SET_BULK = b'\xb8'
GET_BULK = b'\xba'
REMOVE_BULK = b'\xb9'
PLAY_SCRIPT = b'\xb4'

ERROR = b'\xbf'
NO_REPLY = 0x01
EXPIRE = 0x7fffffffffffffff


from ukt.containers import Hash
from ukt.containers import List
from ukt.containers import Set
from ukt.exceptions import KTError
from ukt.exceptions import ProtocolError
from ukt.exceptions import ServerConnectionError
from ukt.exceptions import ServerError
from ukt.exceptions import ServerTimeoutError
from ukt.exceptions import SignalTimeout
from ukt.queue import Queue
from ukt.queue import Schedule
from ukt.queue import SignalQueue
from ukt.serializer import decode
from ukt.serializer import encode
from ukt.serializer import safe_decode
from ukt.serializer import _deserialize_dict
from ukt.serializer import _deserialize_list
from ukt.serializer import _serialize_dict
from ukt.serializer import _serialize_list


num_re = re.compile('-?\d+')
xt_cutoff = 86400 * 180

quote_b = partial(quote_from_bytes, safe='')
unquote_b = partial(unquote_to_bytes)


def decode_from_content_type(content_type):
    if content_type.endswith('colenc=B'):
        return b64decode
    elif content_type.endswith('colenc=U'):
        return unquote_b

def convert_xt(xt):
    if xt is None:
        return EXPIRE
    elif isinstance(xt, datetime.datetime):
        return int(-time.mktime(xt.timetuple()))
    elif isinstance(xt, (int, float)) and xt >= xt_cutoff:
        # Negative expire-times are treated as timestamps. Otherwise, they are
        # treated as relative to current time.
        return -xt
    elif isinstance(xt, datetime.timedelta):
        return xt.total_seconds()
    return xt


READSIZE = 1024 * 4


class Socket(object):
    def __init__(self, s):
        self.sock = s
        self.is_closed = False
        self.buf = io.BytesIO()
        self.bytes_read = self.bytes_written = 0
        self.recvbuf = bytearray(READSIZE)

    def __del__(self):
        if not self.is_closed:
            self.sock.close()

    def _read_from_socket(self, length):
        l = marker = 0
        recvptr = memoryview(self.recvbuf)
        self.buf.seek(self.bytes_written)

        try:
            while True:
                l = self.sock.recv_into(recvptr, READSIZE)
                if not l:
                    self.close()
                    raise ServerConnectionError('server went away')
                self.buf.write(recvptr[:l])
                self.bytes_written += l
                marker += l
                if length > 0 and length > marker:
                    continue
                break
        except socket.timeout:
            self.close()
            raise ServerTimeoutError('timed out reading from socket')
        except socket.error:
            self.close()
            raise ServerConnectionError('error reading from socket')

    def recv(self, length):
        buflen = self.bytes_written - self.bytes_read
        if length > buflen:
            self._read_from_socket(length - buflen)

        self.buf.seek(self.bytes_read)
        data = self.buf.read(length)
        self.bytes_read += length

        if self.bytes_read == self.bytes_written:
            self.purge()
        return data

    def send(self, data):
        try:
            self.sock.sendall(data)
        except socket.timeout:
            self.close()
            raise ServerTimeoutError('timed out writing to socket')
        except socket.error as exc:
            self.close()
            if len(exc.args) == 1:
                errno, errmsg = 'unknown', exc.args[0]
            else:
                errno, errmsg = exc.args[:2]
            raise ServerConnectionError('error %s writing to socket. %s' %
                                        (errno, errmsg))
        except Exception as exc:
            self.close()
            raise exc

    def purge(self):
        self.buf.seek(0)
        self.buf.truncate()
        self.bytes_read = self.bytes_written = 0

    def close(self):
        if self.is_closed:
            return False

        self.is_closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

        self.purge()
        self.buf.close()
        self.buf = None
        return True


class Pool(object):
    def __init__(self, host, port, timeout=None, max_age=3600):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_age = max_age or 3600

        # We keep two sets of sockets around - one for the binary protocol, and
        # another for the HTTP protocol.
        self.in_use = {}
        self.free = []
        self.in_use_http = {}
        self.free_http = []
        self._lock = threading.RLock()

    @property
    def stats(self):
        return (len(self.in_use), len(self.free),
                len(self.in_use_http), len(self.free_http))

    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.timeout:
            sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        return Socket(sock)

    def create_http_client(self):
        conn = HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.connect()
        return conn

    def checkout(self, http=False):
        if http:
            free_list = self.free_http
            in_use = self.in_use_http
            constructor = self.create_http_client
        else:
            free_list = self.free
            in_use = self.in_use
            constructor = self.create_socket

        threshold = time.time() - self.max_age
        with self._lock:
            while free_list:
                ts, sock = heapq.heappop(free_list)
                if ts > threshold:
                    in_use[sock] = ts
                    return sock
                else:
                    sock.close()

            sock = constructor()
            in_use[sock] = time.time()
            return sock

    def checkin(self, sock, http=False):
        threshold = time.time() - self.max_age
        with self._lock:
            if http:
                ts = self.in_use_http.pop(sock)
                if ts < threshold:
                    sock.close()
                elif sock.sock is not None:
                    heapq.heappush(self.free_http, (ts, sock))
            else:
                ts = self.in_use.pop(sock)
                if ts < threshold:
                    sock.close()
                elif not sock.is_closed:
                    heapq.heappush(self.free, (ts, sock))

    def disconnect(self):
        n = 0
        with self._lock:
            free_sockets = itertools.chain(self.free, self.free_http)
            for _, sock in free_sockets:
                sock.close()
                n += 1

            in_use_sockets = itertools.chain(self.in_use, self.in_use_http)
            for sock in in_use_sockets:
                sock.close()
                n += 1

            self.free = []
            self.free_http = []
            self.in_use = {}
            self.in_use_http = {}

        return n


class ScriptRunner(object):
    __slots__ = ('client',)

    def __init__(self, client):
        self.client = client

    def __getattr__(self, attr_name):
        def run_script(__data=None, no_reply=False, encode_values=True,
                       decode_values=True, **kwargs):
            if __data is None:
                __data = kwargs
            elif kwargs:
                __data.update(kwargs)
            return self.client.script(attr_name, __data, no_reply,
                                      encode_values, decode_values)
        return run_script



struct_hi = struct.Struct('>HI')
struct_i = struct.Struct('>I')
struct_ii = struct.Struct('>II')
struct_iii = struct.Struct('>III')
struct_dbkvxt = struct.Struct('>HIIq')


KT_BINARY = 'binary'
KT_JSON = 'json'
KT_MSGPACK = 'msgpack'
KT_NONE = 'none'
KT_PICKLE = 'pickle'


class KyotoTycoon(object):
    """
    Kyoto Tycoon client.

    :param str host: ktserver host.
    :param int port: ktserver port.
    :param int timeout: socket timeout for database connection.
    :param int default_db: default database index.
    :param bool decode_keys: decode keys as utf8-encoded unicode.
    :param serializer: value serialization. Default is KT_BINARY, which treats
        values as utf8-encoded unicode. To disable serialization use KT_NONE.
        Other serializers: KT_JSON, KT_MSGPACK and KT_PICKLE.
    :param encode_value: custom serializer for encoding values as bytestrings.
    :param decode_value: custom deserializer for decoding bytestrings.
    :param int max_age: max idle time for socket in connection pool.
    """
    _content_type = 'text/tab-separated-values; colenc=B'
    _cursor_id = 0

    def __init__(self, host='127.0.0.1', port=1978, timeout=None, default_db=0,
                 decode_keys=True, serializer=None, encode_value=None,
                 decode_value=None, max_age=3600):
        self.host = host
        self.port = port
        self.pool = Pool(host, port, timeout, max_age)
        self.default_db = default_db
        self.decode_keys = decode_keys
        if serializer is None or serializer == KT_BINARY:
            self.encode_value = encode_value or encode
            self.decode_value = decode_value or decode
        elif serializer == KT_MSGPACK:
            if msgpack is None:
                raise ImproperlyConfigured('msgpack library not found')
            self.encode_value = lambda o: msgpack.packb(o, use_bin_type=True)
            self.decode_value = lambda b: msgpack.unpackb(b, raw=False)
        elif serializer == KT_JSON:
            self.encode_value = lambda v: (json
                                           .dumps(v, separators=(',', ':'))
                                           .encode('utf-8'))
            self.decode_value = lambda v: json.loads(v.decode('utf-8'))
        elif serializer == KT_NONE:
            self.encode_value = encode
            self.decode_value = lambda x: x
        elif serializer == KT_PICKLE:
            self.encode_value = partial(pickle.dumps,
                                        protocol=pickle.HIGHEST_PROTOCOL)
            self.decode_value = pickle.loads
        else:
            raise ImproperlyConfigured('unrecognized serializer')

        self._prefix = '/rpc'
        self._headers = {'Content-Type': self._content_type}

    def set_database(self, db=0):
        self.default_db = db

    def close_all(self):
        return self.pool.disconnect()

    @property
    def lua(self):
        if not hasattr(self, '_script_runner'):
            self._script_runner = ScriptRunner(self)
        return self._script_runner

    def serialize_dict(self, d, encode_values=True):
        if encode_values:
            d = {key: self.encode_value(value) for key, value in d.items()}
        return _serialize_dict(d)
    def deserialize_dict(self, data, decode_values=True):
        d = _deserialize_dict(data, False)
        if d and decode_values:
            d = {key: self.decode_value(value) for key, value in d.items()}
        return d

    def serialize_list(self, l, encode_values=True):
        if encode_values:
            l = [self.encode_value(value) for value in l]
        return _serialize_list(l)
    def deserialize_list(self, data, decode_values=True):
        l = _deserialize_list(data, False)
        if l and decode_values:
            l = [self.decode_value(value) for value in l]
        return l

    @contextmanager
    def ctx(self, http=False):
        sock = self.pool.checkout(http)
        try:
            yield sock
        finally:
            self.pool.checkin(sock, http)

    def check_error(self, sock, magic):
        bmagic = sock.recv(1)
        if bmagic == magic:
            return
        elif bmagic == ERROR:
            raise ProtocolError('Internal server error processing request.')
        else:
            raise ServerError('Unexpected server response: %r' % bmagic)

    def get_bulk(self, keys, db=None, decode_values=True):
        """
        Get multiple key/value pairs in a single request.

        :param keys: a list of keys.
        :param int db: database index.
        :param bool decode_values: deserialize values after reading.
        :return: a dict of key, value for matching records.
        """
        with self.ctx() as sock:
            if db is None:
                db = self.default_db

            buf = io.BytesIO()
            buf.write(GET_BULK)
            buf.write(b'\x00\x00\x00\x00')  # No flags.
            buf.write(struct_i.pack(len(keys)))

            for key in keys:
                bkey = encode(key)
                buf.write(struct_hi.pack(db, len(bkey)))
                buf.write(bkey)

            sock.send(buf.getvalue())

            # Check the response status.
            self.check_error(sock, GET_BULK)

            accum = {}
            n_items, = struct_i.unpack(sock.recv(4))
            for i in range(n_items):
                _, klen, vlen, _ = struct_dbkvxt.unpack(sock.recv(18))
                key = sock.recv(klen)
                value = sock.recv(vlen)
                if self.decode_keys:
                    key = safe_decode(key)
                accum[key] = value

            # Decode values in 2nd pass so that a failure to decode doesn't
            # leave the socket in an invalid state.
            if decode_values:
                for key in accum:
                    accum[key] = self.decode_value(accum[key])

        return accum

    def get_bulk_details(self, db_key_list, decode_values=True):
        """
        Get all data for a given list of db, key pairs.

        :param db_key_list: a list of (db, key) tuples.
        :param bool decode_values: deserialize values after reading.
        :return: a list of (db, key, value, xt) tuples.
        """
        with self.ctx() as sock:
            buf = io.BytesIO()
            buf.write(GET_BULK)
            buf.write(b'\x00\x00\x00\x00')  # No flags.
            buf.write(struct_i.pack(len(db_key_list)))

            for db, key in db_key_list:
                bkey = encode(key)
                buf.write(struct_hi.pack(db, len(bkey)))
                buf.write(bkey)

            sock.send(buf.getvalue())

            # Check the response status.
            self.check_error(sock, GET_BULK)

            accum = []
            n_items, = struct_i.unpack(sock.recv(4))
            for i in range(n_items):
                db, klen, vlen, xt = struct_dbkvxt.unpack(sock.recv(18))
                key = sock.recv(klen)
                value = sock.recv(vlen)
                if self.decode_keys:
                    key = safe_decode(key)
                accum.append((db, key, value, xt))

            if decode_values:
                accum = [(db, key, self.decode_value(value), xt)
                         for (db, key, value, xt) in accum]

        return accum

    def get(self, key, db=None, decode_value=True):
        """
        Get the value for a given key.

        :param key: key to fetch.
        :param int db: database index.
        :param bool decode_value: deserialize value after reading.
        :return: value or None.
        """
        if db is None:
            db = self.default_db
        db_key_list = ((db, key),)
        result = self.get_bulk_details(db_key_list, decode_value)
        if result:
            return result[0][2]

    def get_bytes(self, key, db=None):
        """
        Get the bytes at a given key. Short-hand for get(..decode_value=False).

        :param key: key to fetch.
        :param int db: database index.
        :return: value or None.
        """
        return self.get(key, db, False)

    def set_bulk(self, data, db=None, expire_time=None, no_reply=False,
                 encode_values=True):
        """
        Set multiple key/value pairs in a single request.

        :param dict data: a mapping of key to value.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool no_reply: do not receive a response.
        :param bool encode_values: serialize values before writing.
        :return: number of records written.
        """
        with self.ctx() as sock:
            if db is None:
                db = self.default_db
            expire_time = convert_xt(expire_time)

            buf = io.BytesIO()
            buf.write(SET_BULK)
            buf.write(struct_i.pack(NO_REPLY if no_reply else 0))
            buf.write(struct_i.pack(len(data)))

            for key, value in data.items():
                bkey = encode(key)
                if encode_values:
                    bval = self.encode_value(value)
                else:
                    bval = encode(value)
                buf.write(struct_dbkvxt.pack(db, len(bkey), len(bval),
                                             expire_time))
                buf.write(bkey)
                buf.write(bval)

            sock.send(buf.getvalue())
            if not no_reply:
                self.check_error(sock, SET_BULK)
                result, = struct_i.unpack(sock.recv(4))
                return result

    def set_bulk_details(self, data, no_reply=False, encode_values=True):
        """
        Set multiple key/value pairs in a single request, optionally across
        multiple databases with varying expire time(s).

        :param list data: a list of (db, key, value, xt) tuples.
        :param bool no_reply: do not receive a response.
        :param bool encode_values: serialize values before writing.
        :return: number of records written.
        """
        with self.ctx() as sock:
            buf = io.BytesIO()
            buf.write(SET_BULK)
            buf.write(struct_i.pack(NO_REPLY if no_reply else 0))
            buf.write(struct_i.pack(len(data)))

            for db, key, value, xt in data:
                bkey = encode(key)
                if encode_values:
                    bval = self.encode_value(value)
                else:
                    bval = encode(value)
                xt = convert_xt(xt)
                buf.write(struct_dbkvxt.pack(db, len(bkey), len(bval), xt))
                buf.write(bkey)
                buf.write(bval)

            sock.send(buf.getvalue())
            if not no_reply:
                self.check_error(sock, SET_BULK)
                result, = struct_i.unpack(sock.recv(4))
                return result

    def set(self, key, value, db=None, expire_time=None, no_reply=False,
            encode_value=True):
        """
        Set a single key/value pair.

        :param key: key.
        :param value: value to store.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool no_reply: do not receive a response.
        :param bool encode_value: serialize value before writing.
        :return: number of records written (1).
        """
        return self.set_bulk({key: value}, db, expire_time, no_reply,
                             encode_value)

    def set_bytes(self, key, value, db=None, expire_time=None, no_reply=False):
        return self.set(key, value, db, expire_time, no_reply, False)

    def remove_bulk(self, keys, db=None, no_reply=False):
        """
        Remove multiple key/value pairs in a single request.

        :param keys: a list of keys.
        :param int db: database index.
        :param bool no_reply: do not receive a response.
        :return: number of records removed.
        """
        with self.ctx() as sock:
            if db is None:
                db = self.default_db

            buf = io.BytesIO()
            buf.write(REMOVE_BULK)
            buf.write(struct_i.pack(NO_REPLY if no_reply else 0))
            buf.write(struct_i.pack(len(keys)))
            for key in keys:
                bkey = encode(key)
                buf.write(struct_hi.pack(db, len(bkey)))
                buf.write(bkey)

            sock.send(buf.getvalue())
            if not no_reply:
                self.check_error(sock, REMOVE_BULK)
                result, = struct_i.unpack(sock.recv(4))
                return result

    def remove_bulk_details(self, db_key_list, no_reply=False):
        """
        Remove a given list keys. The input is a list of ``(db, key)`` tuples.

        :param db_key_list: a list of (db, key) tuples.
        :param bool no_reply: do not receive a response.
        :return: number of records removed.
        """
        with self.ctx() as sock:
            buf = io.BytesIO()
            buf.write(REMOVE_BULK)
            buf.write(struct_i.pack(NO_REPLY if no_reply else 0))
            buf.write(struct_i.pack(len(db_key_list)))
            for db, key in db_key_list:
                bkey = encode(key)
                buf.write(struct_hi.pack(db, len(bkey)))
                buf.write(bkey)

            sock.send(buf.getvalue())
            if not no_reply:
                self.check_error(sock, REMOVE_BULK)
                result, = struct_i.unpack(sock.recv(4))
                return result

    def remove(self, key, db=None, no_reply=False):
        """
        Remove a single key from the database.

        :param key: key to remove.
        :param int db: database index.
        :param bool no_reply: do not receive a response.
        :return: number of records removed.
        """
        return self.remove_bulk((key,), db, no_reply)

    def script(self, name, data=None, no_reply=False, encode_values=True,
               decode_values=True, _decode_keys=None):
        """
        Evaluate a lua script.

        :param name: script function name.
        :param dict data: dictionary of key/value pairs, passed as arguments.
        :param bool no_reply: do not receive a response.
        :param bool encode_values: serialize values before sending to db.
        :param bool decode_values: deserialize values after reading result.
        :return: dictionary of key/value pairs returned by the lua function.
        """
        decode_keys = (self.decode_keys if _decode_keys is None
                       else _decode_keys)

        flags = NO_REPLY if no_reply else 0
        bname = encode(name)
        data = data or {}

        with self.ctx() as sock:
            buf = io.BytesIO()
            buf.write(PLAY_SCRIPT)
            buf.write(struct.pack('>III', flags, len(bname), len(data)))
            buf.write(bname)

            for key, value in data.items():
                bkey = encode(key)
                if encode_values:
                    bval = self.encode_value(value)
                else:
                    bval = encode(value)

                buf.write(struct_ii.pack(len(bkey), len(bval)))
                buf.write(bkey)
                buf.write(bval)

            sock.send(buf.getvalue())

            if no_reply:
                return

            self.check_error(sock, PLAY_SCRIPT)
            accum = {}
            n_items, = struct_i.unpack(sock.recv(4))
            for i in range(n_items):
                klen, vlen = struct_ii.unpack(sock.recv(8))
                key = sock.recv(klen)
                value = sock.recv(vlen)
                if decode_keys:
                    key = safe_decode(key)
                accum[key] = value

            if decode_values:
                for key in accum:
                    accum[key] = self.decode_value(accum[key])

        return accum

    def raw_script(self, name, data=None, no_reply=False):
        """
        Evaluate a lua script and return the result with no post-processing.

        :param name: script function name.
        :param dict data: dictionary of key/value pairs, passed as arguments.
        :param bool no_reply: do not receive a response.
        :return: dictionary of key/value pairs returned by the lua function.
        """
        return self.script(name, data, no_reply, False, False, False)

    # HTTP helpers.

    def _encode_keys_values(self, data):
        accum = []
        for key, value in data.items():
            bkey = encode(key)
            bval = encode(value)
            accum.append(b'%s\t%s' % (b64encode(bkey), b64encode(bval)))
        return b'\n'.join(accum)

    def _encode_keys(self, keys):
        accum = []
        for key in keys:
            accum.append(b'%s\t' % b64encode(b'_' + encode(key)))
        return b'\n'.join(accum)

    def _decode_response(self, tsv, content_type, decode_keys=None):
        if decode_keys is None:
            decode_keys = self.decode_keys
        decoder = decode_from_content_type(content_type)
        accum = {}
        for line in tsv.split(b'\n'):
            try:
                key, value = line.split(b'\t', 1)
            except ValueError:
                continue

            if decoder is not None:
                key, value = decoder(key), decoder(value)

            if decode_keys:
                key = safe_decode(key)
            accum[key] = value

        return accum

    def _request(self, path, data, db=None, allowed_status=None, atomic=False,
                 decode_keys=None, signal=None, wait=None, send=False):
        if isinstance(data, dict):
            body = self._encode_keys_values(data)
        elif isinstance(data, list):
            body = self._encode_keys(data)
        else:
            body = data

        prefix = {}
        if db is not False:
            prefix['DB'] = self.default_db if db is None else db
        if atomic:
            prefix['atomic'] = ''
        if signal is not None:
            if wait is not None:
                prefix['WAIT'] = signal
                prefix['WAITTIME'] = wait
            elif send:
                prefix['SIGNAL'] = signal
                prefix['SIGNALBROAD'] = ''
            else:
                raise ValueError('signal must specify either a wait-time or '
                                 'indicating signal is being sent.')

        if prefix:
            db_data = self._encode_keys_values(prefix)
            if body:
                body = b'\n'.join((db_data, body))
            else:
                body = db_data

        with self.ctx(http=True) as conn:
            try:
                conn.request('POST', self._prefix + path, body, self._headers)
                response = conn.getresponse()
                content = response.read()
                content_type = response.getheader('content-type')
                status = response.status
            except Exception as exc:
                conn.close()
                raise

        if status != 200:
            if status == 503 and signal is not None:
                raise SignalTimeout('%s timed out waiting for signal' % path)
            elif allowed_status is None or status not in allowed_status:
                raise ProtocolError('protocol error [%s]' % status)

        data = self._decode_response(content, content_type, decode_keys)
        return data, status

    # HTTP API.

    def report(self, **kw):
        """
        Request report from the server.

        :return: a dictionary of metadata about the server state.
        """
        resp, status = self._request('/report', {}, None, **kw)
        return resp

    def status(self, db=None, **kw):
        """
        Request status from the server for the given database.

        :param int db: database index.
        :return: a dictionary of metadata about the database.
        """
        resp, st = self._request('/status', {}, db, decode_keys=True, **kw)
        accum = {}
        for key, value in resp.items():
            value = decode(value)
            if num_re.match(value):
                value = int(value)
            accum[key] = value

        return accum

    def list_databases(self):
        """
        Helper for reading database properties from report and status.

        :return: list of 2-tuples consisting of database path and status dict.
        """
        return [(path, self.status(db=db)) for db, path
                in enumerate(self.databases)]

    @property
    def databases(self):
        """
        :return: list of database paths.
        """
        accum = []
        report = self.report(decode_keys=True)

        for key, value in report.items():
            if not key.startswith('db_'): continue
            suffix = key.rsplit('_', 1)[-1]
            if not suffix.isdigit(): continue

            db_idx = int(suffix)

            # Value is of the format: count=X size=Y path=Z. We ignore count
            # and size, as we will pull these from the /status API anyways.
            path = value.decode('utf8').split(' ', 2)[-1]
            accum.append((db_idx, path.split('=', 1)[-1]))

        return [path for _, path in sorted(accum)]

    def clear(self, db=None, **kw):
        """
        Remove all data from the database.

        :param int db: database index.
        :return: boolean indicating success.
        """
        resp, status = self._request('/clear', {}, db, **kw)
        return status == 200

    def synchronize(self, hard=False, command=None, db=None, **kw):
        """
        Synchronize all data to disk.

        :param bool hard: perform a hard sync.
        :param str command: command to execute after synchronization.
        :param int db: database index.
        :return: boolean indicating success.
        """
        data = {}
        if hard:
            data['hard'] = ''
        if command is not None:
            data['command'] = command
        _, status = self._request('/synchronize', data, db, **kw)
        return status == 200

    def get_http(self, key, db=None, decode_value=True, **kw):
        """
        Get a key using the HTTP API.

        :param key: key.
        :param int db: database index.
        :param bool decode_value: decode value using serializer.
        :return: value or None if not found.
        """
        resp, status = self._request('/get', {'key': key}, db, (450,),
                                     decode_keys=False, **kw)
        if status == 450:
            return
        value = resp[b'value']
        if decode_value:
            value = self.decode_value(value)
        return value

    def remove_http(self, key, db=None, **kw):
        """
        Remove a key using the HTTP API.

        :param key: key.
        :param int db: database index.
        :return: number of records removed (1 or 0).
        """
        resp, status = self._request('/remove', {'key': key}, db, (450,),
                                     decode_keys=False, **kw)
        return 0 if status == 450 else 1

    def set_bulk_http(self, data, db=None, expire_time=None, atomic=True,
                      encode_values=True, **kw):
        """
        Set multiple key/value pairs in one operation using the HTTP API.

        :param dict data: key/value mapping.
        :param int db: database index.
        :param expire_time: expire time in seconds.
        :param bool atomic: set all data in a single operation.
        :param bool encode_values: serialize values.
        :return: number of records set.
        """
        accum = {}
        if expire_time is not None:
            accum['xt'] = str(convert_xt(expire_time))
        for key, value in data.items():
            if encode_values:
                value = self.encode_value(value)
            accum['_%s' % key] = value

        resp, status = self._request('/set_bulk', accum, db, atomic=atomic,
                                     decode_keys=False, **kw)
        return int(resp[b'num'])

    def remove_bulk_http(self, keys, db=None, atomic=True, **kw):
        """
        Remove multiple keys using the HTTP API.

        :param list keys: keys to remove.
        :param int db: database index.
        :param bool atomic: remove keys in a single operation.
        :return: number of records removed.
        """
        resp, status = self._request('/remove_bulk', keys, db, atomic=atomic,
                                     decode_keys=False, **kw)
        return int(resp[b'num'])

    def _simple_write(self, cmd, key, value, db=None, expire_time=None,
                      encode_value=True, **kw):
        if encode_value:
            value = self.encode_value(value)
        data = {'key': key, 'value': value}
        if expire_time is not None:
            data['xt'] = str(convert_xt(expire_time))
        resp, status = self._request('/%s' % cmd, data, db, (450,),
                                     decode_keys=False, **kw)
        return status != 450

    def set_http(self, key, value, db=None, expire_time=None,
                 encode_value=True, **kw):
        """
        Set a single key/value pair using the HTTP API.

        :param key: key.
        :param value: value to store.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool encode_value: serialize value before writing.
        :return: True on success.
        """
        return self._simple_write('set', key, value, db, expire_time,
                                  encode_value, **kw)

    def add(self, key, value, db=None, expire_time=None, encode_value=True,
            **kw):
        """
        Add a single key/value pair without overwriting an existing key.

        :param key: key.
        :param value: value to store.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool encode_value: serialize value before writing.
        :return: True on success.
        """
        return self._simple_write('add', key, value, db, expire_time,
                                  encode_value, **kw)

    def replace(self, key, value, db=None, expire_time=None,
                encode_value=True, **kw):
        """
        Replace a single key/value pair without creating a new key.

        :param key: key.
        :param value: value to store.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool encode_value: serialize value before writing.
        :return: True on success.
        """
        return self._simple_write('replace', key, value, db, expire_time,
                                  encode_value, **kw)

    def append(self, key, value, db=None, expire_time=None, encode_value=True,
               **kw):
        """
        Append data to the value of a given key pair.

        :param key: key.
        :param value: value to append..
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool encode_value: serialize value before writing.
        :return: True on success.
        """
        return self._simple_write('append', key, value, db, expire_time,
                                  encode_value, **kw)

    def increment(self, key, n=1, orig=None, db=None, expire_time=None, **kw):
        """
        Atomically increment the value stored in the given key.

        :param key: key.
        :param int n: amount to increment by.
        :param int orig: original value if key does not exist.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :return: value after increment.
        """
        data = {'key': key, 'num': str(n)}
        if orig is not None:
            data['orig'] = str(orig)
        if expire_time is not None:
            data['xt'] = str(convert_xt(expire_time))
        resp, status = self._request('/increment', data, db,
                                     decode_keys=False, **kw)
        return int(resp[b'num'])

    def increment_double(self, key, n=1, orig=None, db=None, expire_time=None,
                         **kw):
        """
        Atomically increment a double-precision value stored in the given key.

        :param key: key.
        :param float n: amount to increment by.
        :param float orig: original value if key does not exist.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :return: value after increment.
        """
        data = {'key': key, 'num': str(n)}
        if orig is not None:
            data['orig'] = str(orig)
        if expire_time is not None:
            data['xt'] = str(convert_xt(expire_time))
        resp, status = self._request('/increment_double', data, db,
                                     decode_keys=False, **kw)
        return float(resp[b'num'])

    def cas(self, key, old_val, new_val, db=None, expire_time=None,
            encode_value=True, **kw):
        """
        Perform an atomic compare-and-set.

        :param key: key.
        :param old_val: original value in database.
        :param new_val: new value for key.
        :param int db: database index.
        :param expire_time: expire time in seconds from now.
        :param bool encode_value: serialize value before writing.
        :return: True on success.
        """
        if old_val is None and new_val is None:
            raise ValueError('old value and/or new value must be specified.')

        data = {'key': key}
        if old_val is not None:
            if encode_value:
                old_val = self.encode_value(old_val)
            data['oval'] = old_val
        if new_val is not None:
            if encode_value:
                new_val = self.encode_value(new_val)
            data['nval'] = new_val
        if expire_time is not None:
            data['xt'] = str(convert_xt(expire_time))

        resp, status = self._request('/cas', data, db, (450,), **kw)
        return status != 450

    def check(self, key, db=None, **kw):
        """
        Test if the given key exists.

        :param key: key to check.
        :param int db: database index.
        :return: True if key exists.
        """
        resp, status = self._request('/check', {'key': key}, db, (450,), **kw)
        return status != 450

    exists = check

    def length(self, key, db=None, **kw):
        """
        Get the length of the value stored in the given key.

        :param key: key to check.
        :param int db: database index.
        :return: length of value or None if key does not exist.
        """
        resp, status = self._request('/check', {'key': key}, db, (450,),
                                     decode_keys=False, **kw)
        if status == 200:
            return int(resp[b'vsiz'])

    def seize(self, key, db=None, decode_value=True, **kw):
        """
        Atomic get and delete for a given key.

        :param key: key to pop.
        :param int db: database index.
        :param bool decode_value: deserialize the value after reading.
        :return: value from database.
        """
        resp, status = self._request('/seize', {'key': key}, db, (450,),
                                     decode_keys=False, **kw)
        if status == 450:
            return
        value = resp[b'value']
        if decode_value:
            value = self.decode_value(value)
        return value

    def vacuum(self, step=0, db=None, **kw):
        """
        Vacuum the database.

        :param int step: step increment.
        :param int db: database index.
        :return: True on success.
        """
        # If step > 0, the whole region is scanned.
        data = {'step': str(step)} if step > 0 else {}
        resp, status = self._request('/vacuum', data, db, **kw)
        return status == 200

    def _do_bulk_command(self, cmd, params, db=None, decode_values=True, **kw):
        resp, status = self._request(cmd, params, db, **kw)

        n = resp.pop('num' if self.decode_keys else b'num')
        if n == b'0':
            return {}

        accum = {}
        for key, value in resp.items():
            if decode_values:
                value = self.decode_value(value)
            accum[key[1:]] = value
        return accum

    def _do_bulk_sorted_command(self, cmd, params, db=None, **kw):
        res = self._do_bulk_command(cmd, params, db, decode_values=False, **kw)
        return sorted(res, key=lambda k: int(res[k]))

    def get_bulk_http(self, keys, db=None, decode_values=True, atomic=True,
                      **kw):
        return self._do_bulk_command('/get_bulk', keys, db, decode_values,
                                     atomic=atomic, **kw)

    def match_prefix(self, prefix, max_keys=None, db=None, **kw):
        """
        Return sorted list of keys that match the given prefix.

        :param str prefix: key prefix.
        :param int max_keys: maximum number of keys to return.
        :param int db: database index.
        :return: a sorted list of matching keys.
        """
        data = {'prefix': prefix}
        if max_keys is not None:
            data['max'] = str(max_keys)
        return self._do_bulk_sorted_command('/match_prefix', data, db, **kw)

    def match_regex(self, regex, max_keys=None, db=None, **kw):
        """
        Return sorted list of keys that match the given regex.

        :param str regex: key regular expression.
        :param int max_keys: maximum number of keys to return.
        :param int db: database index.
        :return: a sorted list of matching keys.
        """
        data = {'regex': regex}
        if max_keys is not None:
            data['max'] = str(max_keys)
        return self._do_bulk_sorted_command('/match_regex', data, db, **kw)

    def match_similar(self, origin, distance=None, max_keys=None, db=None,
                      **kw):
        """
        Return sorted list of keys that are within a given edit distance from
        a string.

        :param str origin: source string.
        :param int distance: maximum edit distance.
        :param int max_keys: maximum number of keys to return.
        :param int db: database index.
        :return: a sorted list of matching keys.
        """
        data = {'origin': origin, 'utf': 'true'}
        if distance is not None:
            data['range'] = str(distance)
        if max_keys is not None:
            data['max'] = str(max_keys)
        return self._do_bulk_sorted_command('/match_similar', data, db, **kw)

    def _cursor_command(self, cmd, cursor_id, data, db=None, **kw):
        data['CUR'] = cursor_id
        resp, status = self._request('/%s' % cmd, data, db, (450, 501),
                                    decode_keys=False, **kw)
        if status == 501:
            raise NotImplementedError('%s is not supported' % cmd)
        return resp, status

    def cur_jump(self, cursor_id, key=None, db=None, **kw):
        data = {'key': key} if key else {}
        _, s = self._cursor_command('cur_jump', cursor_id, data, db, **kw)
        return s == 200

    def cur_jump_back(self, cursor_id, key=None, db=None, **kw):
        data = {'key': key} if key else {}
        _, s = self._cursor_command('cur_jump_back', cursor_id, data, db, **kw)
        return s == 200

    def cur_step(self, cursor_id, **kw):
        _, status = self._cursor_command('cur_step', cursor_id, {}, **kw)
        return status == 200

    def cur_step_back(self, cursor_id, **kw):
        _, status = self._cursor_command('cur_step_back', cursor_id, {}, **kw)
        return status == 200

    def cur_set_value(self, cursor_id, value, step=False, expire_time=None,
                      encode_value=True, **kw):
        if encode_value:
            value = self.encode_value(value)
        data = {'value': value}
        if expire_time is not None:
            data['xt'] = str(convert_xt(expire_time))
        if step:
            data['step'] = ''
        _, s = self._cursor_command('cur_set_value', cursor_id, data, **kw)
        return s == 200

    def cur_remove(self, cursor_id, **kw):
        _, status = self._cursor_command('cur_remove', cursor_id, {}, **kw)
        return status == 200

    def cur_get_key(self, cursor_id, step=False, **kw):
        data = {'step': ''} if step else {}
        r, status = self._cursor_command('cur_get_key', cursor_id, data, **kw)
        if status == 450:
            return
        key = r[b'key']
        return safe_decode(key) if self.decode_keys else key

    def cur_get_value(self, cursor_id, step=False, decode_value=True, **kw):
        data = {'step': ''} if step else {}
        r, s = self._cursor_command('cur_get_value', cursor_id, data, **kw)
        if s == 450:
            return
        value = r[b'value']
        return self.decode_value(value) if decode_value else value

    def cur_get(self, cursor_id, step=False, decode_value=True, **kw):
        data = {'step': ''} if step else {}
        resp, status = self._cursor_command('cur_get', cursor_id, data, **kw)
        if status == 450:
            return
        key = resp[b'key']
        if self.decode_keys:
            key = safe_decode(key)
        value = resp[b'value']
        if decode_value:
            value = self.decode_value(value)
        return (key, value)

    def cur_seize(self, cursor_id, decode_value=True, **kw):
        resp, status = self._cursor_command('cur_seize', cursor_id, {}, **kw)
        if status == 450:
            return
        key = resp[b'key']
        if self.decode_keys:
            key = safe_decode(key)
        value = resp[b'value']
        if decode_value:
            value = self.decode_value(value)
        return (key, value)

    def cur_delete(self, cursor_id, **kw):
        resp, status = self._cursor_command('cur_delete', cursor_id, {}, **kw)
        return status == 200

    def cursor(self, cursor_id=None, db=None, decode_values=True,
               encode_values=True):
        """
        Obtain a cursor for iterating over the database.

        :param int cursor_id: optional ID for cursor.
        :param int db: database index.
        :param bool decode_values: decode values read from the cursor.
        :param bool encode_values: encode values written using the cursor.
        :return: a :py:class:`Cursor`.
        """
        if cursor_id is None:
            KyotoTycoon._cursor_id += 1
            cursor_id = KyotoTycoon._cursor_id
        return Cursor(self, cursor_id, db, decode_values, encode_values)

    def ulog_list(self):
        resp, status = self._request('/ulog_list', {}, None, decode_keys=True)
        log_list = []
        for filename, meta in resp.items():
            size, ts_str = meta.decode('utf-8').split(':')
            ts = datetime.datetime.fromtimestamp(int(ts_str) / 1e9)
            log_list.append((filename, size, ts))
        return log_list

    def ulog_remove(self, max_dt=None):
        max_dt = max_dt or datetime.datetime.now()
        data = {'ts': str(int(max_dt.timestamp() * 1e9))}
        resp, status = self._request('/ulog_remove', data, None)
        return status == 200

    def count(self, db=None, **kw):
        """
        Return the number of keys in the given database.

        :param int db: database index.
        :return: number of keys.
        """
        resp = self.status(db, **kw)
        return int(resp.get('count') or 0)

    def size(self, db=None):
        """
        Return the size of the given database in bytes.

        :param int db: database index.
        :return: size in bytes.
        """
        resp = self.status(db)
        return int(resp.get('size') or 0)

    def _key_db_from_item(self, item):
        return item if isinstance(item, tuple) else (item, self.default_db)

    def __getitem__(self, item):
        return self.get(*self._key_db_from_item(item))
    def __setitem__(self, item, value):
        key, db = self._key_db_from_item(item)
        self.set(key, value, db=db)
    def __delitem__(self, item):
        self.remove(*self._key_db_from_item(item))

    def update(self, __data=None, **kwargs):
        if __data is None:
            __data = kwargs
        else:
            __data.update(kwargs)
        return self.set_bulk(__data)
    pop = seize

    def __contains__(self, item):
        return self.check(*self._key_db_from_item(item))

    def __len__(self):
        return self.count()

    def keys(self, db=None):
        cursor = self.cursor(db=db)
        if not cursor.jump(): return
        while True:
            key = cursor.key()
            if key is None: return
            yield key
            if not cursor.step(): return

    def keys_nonlazy(self, db=None):
        return self.match_prefix('', db=db)

    def values(self, db=None):
        cursor = self.cursor(db=db)
        if not cursor.jump(): return
        while True:
            value = cursor.value()
            if value is None: return
            yield value
            if not cursor.step(): return

    def items(self, db=None):
        cursor = self.cursor(db=db)
        if not cursor.jump(): return
        while True:
            kv = cursor.get()
            if kv is None: return
            yield kv
            if not cursor.step(): return

    def __iter__(self):
        return iter(self.keys())

    # Lua helpers, depends on scripts/kt.lua.
    def touch(self, key, xt=None, db=None):
        """
        Run a lua function (touch) defined in scripts/kt.lua that allows one
        to update the TTL / expire time of a key.

        The old expire time is returned. If the key does not exist, then None
        is returned.

        :param str key: key to update.
        :param xt: new expire time (or None).
        :param int db: database index.
        :return: old expire time or None if key not found.
        """
        ret = self.touch_bulk([key], xt, db)
        return ret.get(decode(key) if self.decode_keys else encode(key))

    def touch_bulk(self, keys, xt=None, db=None):
        """
        Run a lua function (touch_bulk) defined in scripts/kt.lua that allows
        one to update the TTL / expire time of multiple keys.

        The return value is a dictionary of key -> old expire time. If the key
        does not exist, then the key is omitted from the return value.

        :param list keys: keys to update.
        :param xt: new expire time (or None).
        :param int db: database index.
        :return: a dict of key -> old expire time.
        """
        data = {'db': self.default_db if db is None else db}
        for key in keys:
            data[key] = str(convert_xt(xt))
        out = self.script('touch_bulk', data=data, encode_values=False,
                          decode_values=False)
        return {key: int(decode(value)) for key, value in out.items()}

    def touch_relative(self, key, n, db=None):
        """
        Run a lua function (touch_bulk_relative) defined in scripts/kt.lua that
        allows one to increment the TTL / expire time of a key.

        The new expire time is returned. If the key does not exist, then None
        is returned.

        :param str key: key to update.
        :param int n: seconds to increase expire-time.
        :param int db: database index.
        :return: new expire time or None if key not found.
        """
        ret = self.touch_bulk_relative([key], n, db)
        return ret.get(decode(key) if self.decode_keys else encode(key))

    def touch_bulk_relative(self, keys, n, db=None):
        """
        Run a lua function (touch_bulk_relative) defined in scripts/kt.lua that
        allows one to update the TTL / expire time of multiple keys.

        The return value is a dictionary of key -> new expire time. If the key
        does not exist, then the key is omitted from the return value.

        :param list keys: keys to update.
        :param int n: seconds to increase expire-time.
        :param int db: database index.
        :return: a dict of key -> new expire time.
        """
        data = {'db': self.default_db if db is None else db}
        for key in keys:
            data[key] = str(n)
        out = self.script('touch_bulk_relative', data=data,
                          encode_values=False, decode_values=False)
        return {key: int(decode(value)) for key, value in out.items()}

    def expire_time(self, key, db=None):
        """
        Get the expire time by running a lua function (expire_time) defined in
        scripts/kt.lua.

        :param str key: key to check.
        :param int db: database index
        :return: expire timestamp or None if key not found.
        """
        data = {'db': self.default_db if db is None else db, 'key': key}
        out = self.raw_script('expire_time', data)
        if out:
            return int(out[b'xt'])

    def expires(self, key, db=None):
        """
        Get the expire time as a datetime.

        :param str key: key to check.
        :param int db: database index
        :return: expire datetime or None if key not found.
        """
        ts = self.expire_time(key, db)
        if not ts:
            return
        elif ts > (10 ** 11):
            return datetime.datetime.max
        return datetime.datetime.fromtimestamp(ts)

    def error(self, db=None):
        """
        Get the last error code and message.

        If the last command was successful, then (0, 'success') is returned.

        :param int db: database index.
        :return: a 2-tuple of (code, message)
        """
        data = {'db': self.default_db if db is None else db}
        out = self.raw_script('get_error', data)
        if out:
            return int(out[b'code']), safe_decode(out[b'message'])

    def Hash(self, key, encode_values=True, decode_values=True, db=None):
        """
        Create a :py:class:`Hash` container instance.
        """
        return Hash(self, key, encode_values, decode_values, db)

    def List(self, key, encode_values=True, decode_values=True, db=None):
        """
        Create a :py:class:`List` container instance.
        """
        return List(self, key, encode_values, decode_values, db)

    def Set(self, key, encode_values=True, decode_values=True, db=None):
        """
        Create a :py:class:`Set` container instance.
        """
        return Set(self, key, encode_values, decode_values, db)

    def Queue(self, key, db=None):
        """
        Create a :py:class:`Queue` instance.
        """
        return Queue(self, key, db)

    def SignalQueue(self, key, signal='q', db=None, wait=10, cursor=None):
        """
        Create a :py:class:`SignalQueue` instance.
        """
        return SignalQueue(self, key, signal, db, wait, cursor)

    def Schedule(self, key, db=None):
        """
        Create a :py:class:`Schedule` instance.
        """
        return Schedule(self, key, db)


class Cursor(object):
    def __init__(self, protocol, cursor_id, db=None, decode_values=True,
                 encode_values=True):
        self.protocol = protocol
        self.cursor_id = cursor_id
        self.db = db
        self._decode_values = decode_values
        self._encode_values = encode_values
        self._initialized = False
        self._valid = False

    def __iter__(self):
        if not self._initialized and not self._valid:
            self.jump()
        return self

    def is_valid(self):
        return self._valid

    def jump(self, key=None, **kw):
        self._initialized = True
        self._valid = self.protocol.cur_jump(self.cursor_id, key, self.db,
                                             **kw)
        return self._valid

    def jump_back(self, key=None, **kw):
        self._initialized = True
        self._valid = self.protocol.cur_jump_back(self.cursor_id, key, self.db,
                                                  **kw)
        return self._valid

    def step(self, **kw):
        self._valid = self.protocol.cur_step(self.cursor_id, **kw)
        return self._valid

    def step_back(self, **kw):
        self._valid = self.protocol.cur_step_back(self.cursor_id, **kw)
        return self._valid

    def key(self, step=False, **kw):
        if self._valid:
            return self.protocol.cur_get_key(self.cursor_id, step, **kw)

    def value(self, step=False, **kw):
        if self._valid:
            return self.protocol.cur_get_value(self.cursor_id, step,
                                               self._decode_values, **kw)

    def get(self, step=False, **kw):
        if self._valid:
            return self.protocol.cur_get(self.cursor_id, step,
                                         self._decode_values, **kw)

    def set_value(self, value, step=False, expire_time=None, **kw):
        if self._valid:
            if not self.protocol.cur_set_value(self.cursor_id, value, step,
                                               expire_time,
                                               self._encode_values, **kw):
                self._valid = False
        return self._valid

    def remove(self, **kw):
        if self._valid:
            if not self.protocol.cur_remove(self.cursor_id, **kw):
                self._valid = False
        return self._valid

    def seize(self, **kw):
        if self._valid:
            kv = self.protocol.cur_seize(self.cursor_id, self._decode_values,
                                         **kw)
            if kv is None:
                self._valid = False
            return kv

    def close(self):
        if self._valid and self.protocol.cur_delete(self.cursor_id):
            self._valid = False
            return True
        return False

    def __next__(self):
        if not self._valid:
            raise StopIteration
        kv = self.protocol.cur_get(self.cursor_id, step=True)
        if kv is None:
            self._valid = False
            raise StopIteration
        return kv
    next = __next__
