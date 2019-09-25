import datetime
import io
import random
import struct
import threading
import time

from ukt.exceptions import ProtocolError
from ukt.exceptions import ReplicationError
from ukt.exceptions import ServerError
from ukt.serializer import safe_decode


REPLICATION = b'\xb1'
SYNC = b'\xb0'

# Defined in kttimeddb.h. The other operations do not result in any replication
# activity, so they are not defined here.
REPL_SET = 0xa1
REPL_REMOVE = 0xa2
REPL_CLEAR = 0xa5

struct_hhb = struct.Struct('>HHB')
struct_i = struct.Struct('>I')
struct_q = struct.Struct('>Q')


class ReplicationClient(object):
    """
    Replication client implementation.

    Receive update logs from a running kyoto tycoon server. Allows
    implementation of custom replication handler, e.g. key filtering or
    pushing change notifications to an external service.

    :param KyotoTycoon kt: client
    :param int sid: replication client's server id (if unspecified will use a
        random integer between 100 - 199.
    :param bool decode_values: attempt to decode values for SET operations
        using the configured serializer.
    """
    def __init__(self, kt, sid=None, decode_values=True):
        self.kt = kt
        self.sid = sid or random.randint(100, 199)
        self.decode_values = decode_values
        self._running = False
        self._finished = threading.Event()

    def run(self, timestamp=None):
        """
        Returns a generator that yields update-log messages.

        Each message is a `dict` with (at least) the following keys:

        * sid - server id where change originated
        * db - database index
        * op - one of REPL_SET, REPL_REMOVE, REPL_CLEAR

        REPL_REMOVE operations additionally include the key being removed. Note
        that the remove message is sent regardless of whether the requested key
        existed.

        REPL_SET operations include the key being set, the value, and the
        expiration time (xt). If no expiration time was set, then the xt value
        will be 0xffffffffff. Otherwise it is a unix timestamp.

        Multi-key operations such as remove_bulk or set_bulk will result in one
        update-log per item.
        """
        if self._running:
            return False

        self._running = True
        self._finished.clear()

        if timestamp is None:
            timestamp = time.time()
        elif isinstance(timestamp, datetime.datetime):
            timestamp = timestamp.timestamp()

        timestamp = int(timestamp * 10**9)  # Timestamp expressed in ns.
        try:
            yield from self._run(timestamp)
        finally:
            self._running = False
            self._finished.set()

    def _run(self, timestamp):
        with self.kt.ctx() as sock:
            buf = io.BytesIO()
            buf.write(REPLICATION)
            buf.write(b'\x00\x00\x00\x00')  # Flags (0).
            buf.write(struct.pack('>QH', timestamp, self.sid))
            sock.send(buf.getvalue())

            self.kt.check_error(sock, REPLICATION)

            while self._running:
                magic_ts = sock.recv(9)
                magic = magic_ts[:1]
                if magic == SYNC:
                    sock.send(REPLICATION)
                    continue
                elif magic != REPLICATION:
                    raise ServerError('Unexpected response: %r' % magic)

                nbytes, = struct_i.unpack(sock.recv(4))
                data = sock.recv(nbytes)
                yield self._parse_ulog(memoryview(data))

    def _parse_ulog(self, data):
        sid, db, op = struct_hhb.unpack(data[:5])
        log = {'sid': sid, 'db': db, 'op': op}
        buf = data[5:]

        if op == REPL_REMOVE:
            ksiz, buf = self._read_varnum(buf)
            key = buf[:ksiz].tobytes()
            if self.kt.decode_keys:
                key = safe_decode(key)
            log['key'] = key
        elif op == REPL_SET:
            ksiz, buf = self._read_varnum(buf)
            vsiz, buf = self._read_varnum(buf)
            key = buf[:ksiz].tobytes()
            if self.kt.decode_keys:
                key = safe_decode(key)
            log['key'] = key
            log['xt'], = struct_q.unpack(b'\x00\x00\x00' + buf[ksiz:ksiz + 5])

            value = buf[ksiz + 5:ksiz + vsiz].tobytes()
            if self.decode_values:
                try:
                    value = self.kt.decode_value(value)
                except Exception:
                    pass
            log['value'] = value
        elif op != REPL_CLEAR:
            raise ReplicationError('unsupported operation: %s' % hex(op))
        return log

    def _read_varnum(self, data):
        value = 0
        for i, b in enumerate(data):
            value = (value << 7) + (b & 0x7f)
            if b < 0x80:
                return (value, data[i + 1:])
        return (0, data)

    def stop(self, wait=False):
        """
        Stop the replication client.

        :param bool wait: wait for running replication client to finish. This
            should ONLY be specified if the replication client is running in a
            separate thread. Otherwise the call will deadlock.
        :return: bool indicating success.
        """
        if not self._running:
            return False
        self._running = False

        if wait:
            # Only specify wait=True if replication is running in a separate
            # thread! Otherwise the code will dead-lock.
            self._finished.wait()
        return True
