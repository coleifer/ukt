import random
import time

from ukt.exceptions import SignalTimeout


class LuaQueue(object):
    """
    Helper-class for working with the Kyoto Tycoon Lua queue functions.
    """
    def __init__(self, client, key, db=None):
        self._client = client
        self._key = key
        self._db = client.default_db if db is None else db

    def _lua(self, fn, **kwargs):
        kwargs.update(queue=self._key, db=self._db)
        return self._client.script(fn, kwargs, encode_values=False,
                                   decode_values=False)

    def add(self, item):
        return int(self._lua('queue_add', data=item)['id'])

    def extend(self, items):
        args = {str(i): item for i, item in enumerate(items)}
        return int(self._lua('queue_madd', **args)['num'])

    def _item_list(self, fn, n=1):
        items = self._lua(fn, n=n)
        if n == 1:
            return items['0'] if items else None

        accum = []
        if items:
            for key in sorted(items, key=int):
                accum.append(items[key])
        return accum

    def pop(self, n=1):
        return self._item_list('queue_pop', n)
    def rpop(self, n=1):
        return self._item_list('queue_rpop', n)

    def peek(self, n=1):
        return self._item_list('queue_peek', n)
    def rpeek(self, n=1):
        return self._item_list('queue_rpeek', n)

    def count(self):
        return int(self._lua('queue_size')['num'])
    __len__ = count

    def remove(self, data, n=None):
        if n is None:
            n = -1
        return int(self._lua('queue_remove', data=data, n=n)['num'])
    def rremove(self, data, n=None):
        if n is None:
            n = -1
        return int(self._lua('queue_rremove', data=data, n=n)['num'])

    def clear(self):
        return int(self._lua('queue_clear')['num'])


class SignalQueue(object):
    def __init__(self, client, key, signal='q', db=None, wait=10, cursor=None):
        self.client = client
        self.key = key
        self.signal = signal
        self.db = client.default_db if db is None else db
        self.wait = wait
        self.cursor_id = cursor or int(random.random() * 1e8)

    def produce(self, value, expire_time=None, encode_value=True):
        """
        Add a new value to the queue.

        Returns a 2-tuple of `(added?, num listeners)`.
        """
        fullkey = '%s:%s' % (self.key, time.time())
        if encode_value:
            value = self.client.encode_value(value)
        data = {'key': fullkey, 'value': value}
        if expire_time is not None:
            data['xt'] = str(expire_time)

        r, s = self.client._request('/add', data, self.db, (450,),
                                    decode_keys=False, signal=self.signal,
                                    send=True)
        if s == 450:
            return False, 0
        else:
            return True, int(r[b'SIGNALED'])

    def consume(self, wait=None):
        """
        Consume data from the queue, blocking until new data arrives.

        A signal is used to reduce latency between producer and consumer, while
        at the same time avoiding polling rapidly. In the event two consumers
        are signalled at the same time, only one of them will be able to read
        the produced value. The other will return `None`.

        Note that waiting on a signal occupies a server thread for the duration
        of the time it is waiting.
        """
        wait = self.wait if wait is None else wait
        ok = self.client.cur_jump(self.cursor_id, self.key, self.db)
        while not ok:
            try:
                ok = self.client.cur_jump(self.cursor_id, self.key, self.db,
                                          signal=self.signal, wait=wait)
            except SignalTimeout:
                return

        resp = self.client.cur_seize(self.cursor_id)
        if resp is not None:
            return resp[1]

    def flush(self):
        keys = self.client.match_prefix(self.key + ':')
        return self.client.remove_bulk(keys)
