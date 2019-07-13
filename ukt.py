from contextlib import contextmanager
import heapq
import io
import socket
import struct
import time


class KTError(Exception): pass
class ProtocolError(KTError): pass
class ServerConnectionError(KTError): pass
class ServerError(KTError): pass


SET_BULK = b'\xb8'
GET_BULK = b'\xba'
REMOVE_BULK = b'\xb9'
PLAY_SCRIPT = b'\xb4'
ERROR = b'\xbf'
NO_REPLY = 0x01
EXPIRE = 0x7fffffffffffffff


def encode(s):
    if isinstance(s, str):
        return s.encode('utf8')
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        return str(s).encode('utf8')

def decode(s):
    if isinstance(s, bytes):
        return s.decode('utf8')
    elif isinstance(s, str):
        return s
    elif s is not None:
        return str(s)


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
            raise ServerConnectionError('timed out reading from socket')
        except socket.error:
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
        except IOError:
            self.close()
            raise ServerConnectionError('server went away')

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
        self.in_use = set()
        self.free = []

    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.timeout:
            sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        return Socket(sock)

    def checkout(self):
        threshold = time.time() - self.max_age
        while self.free:
            ts, sock = heapq.heappop(self.free)
            if ts > threshold:
                self.in_use.add(sock)
                return sock
            else:
                sock.close()

        sock = self.create_socket()
        self.in_use.add(sock)
        return sock

    def checkin(self, sock):
        self.in_use.remove(sock)
        if not sock.is_closed:
            heapq.heappush(self.free, (time.time(), sock))

    def close(self):
        n = 0
        while self.free:
            _, sock = self.free.pop()
            sock.close()
            n += 1

        tmp, self.in_use = self.in_use, set()
        for sock in tmp:
            sock.close()
            n += 1

        return n


class Ctx(object):
    __slots__ = ('pool', 'sock')

    def __init__(self, pool):
        self.pool = pool
        self.sock = None

    def __enter__(self):
        self.sock = self.pool.checkout()
        return self.sock

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pool.checkin(self.sock)


class Protocol(object):
    def __init__(self, host='127.0.0.1', port=1978, decode_keys=True,
                 encode_value=None, decode_value=None, timeout=None,
                 max_age=3600):
        self.pool = Pool(host, port, timeout, max_age)
        self.decode_keys = decode_keys
        self.encode_value = encode_value or encode
        self.decode_value = decode_value or decode

    @contextmanager
    def ctx(self):
        sock = self.pool.checkout()
        try:
            yield sock
        except socket.error:
            sock.close()
        finally:
            self.pool.checkin(sock)

    def get_bulk(self, keys, db=None, decode_values=True):
        """
        Get multiple key/value pairs in a single request.

        :param keys: a list of keys.
        :param int db: database index.
        :param bool decode_values: deserialize values after reading.
        :return: a dict of key, value for matching records.
        """
        with self.ctx() as sock:
            pass

    def get_bulk_details(self, db_key_list, decode_values=True):
        """
        Get all data for a given list of db, key pairs.

        :param db_key_list: a list of (db, key) tuples.
        :param bool decode_values: deserialize values after reading.
        :return: a list of (db, key, value, xt) tuples.
        """
        with self.ctx() as sock:
            pass

    def get(self, key, db=None, decode_value=True):
        """
        Get the value for a given key.

        :param key: key to fetch.
        :param int db: database index.
        :param bool decode_value: deserialize value after reading.
        :return: value or None.
        """
        db_key_list = ((db, key),)
        result = self.get_bulk_details(db_key_list, decode_value)
        if result:
            return result[0][2]

    def set_bulk(self, data, db=None, expire_time=None, no_reply=False,
                 encode_values=True):
        """
        Set multiple key/value pairs in a single request.

        :param dict data: a mapping of key to value.
        :param int db: database index.
        :param long expire_time: expire time in seconds from now.
        :param bool no_reply: do not receive a response.
        :param bool encode_values: serialize values before writing.
        :return: number of records written.
        """
        with self.ctx() as sock:
            pass

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
            pass

    def set(self, key, value, db=None, expire_time=None, no_reply=False,
            encode_value=True):
        return self.set_bulk({key: value}, db, expire_time, no_reply,
                             encode_value)

    def remove_bulk(self, keys, db=None, no_reply=False):
        """
        Remove multiple key/value pairs in a single request.

        :param keys: a list of keys.
        :param int db: database index.
        :param bool no_reply: do not receive a response.
        :return: number of records removed.
        """
        with self.ctx() as sock:
            pass

    def remove_bulk_details(self, db_key_list, no_reply=False):
        """
        Get all data for a given list of db, key pairs.

        :param db_key_list: a list of (db, key) tuples.
        :param bool no_reply: do not receive a response.
        :return: number of records removed.
        """
        with self.ctx() as sock:
            pass

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
               decode_values=True):
        """
        Evaluate a lua script.

        :param name: script function name.
        :param dict data: dictionary of key/value pairs, passed as arguments.
        :param bool no_reply: do not receive a response.
        :param bool encode_values: serialize values before sending to db.
        :param bool decode_values: deserialize values after reading result.
        :return: dictionary of key/value pairs returned by the lua function.
        """
        with self.ctx() as sock:
            pass
