import random
import time

from ukt.exceptions import SignalTimeout


class Queue(object):
    """
    Helper-class for working with the Kyoto Tycoon Lua queue functions.
    """
    def __init__(self, client, key, db=None):
        self.kt = client
        self._key = key
        self._db = client.default_db if db is None else db

    def _lua(self, fn, raw_data=None, value_data=None):
        data = {'queue': self._key, 'db': self._db}
        if raw_data is not None:
            data.update(raw_data)

        if value_data:
            for key, value in value_data.items():
                data[key] = self.kt.encode_value(value)

        return self.kt.raw_script(fn, data)

    def add(self, item, score=None):
        raw_data = {'score': score} if score is not None else {}
        return int(self._lua('queue_add', raw_data, {'data': item})[b'id'])

    def extend(self, items, score=None):
        raw_data = {'score': score} if score is not None else {}
        value_data = {str(i): item for i, item in enumerate(items)}
        return int(self._lua('queue_madd', raw_data, value_data)[b'num'])

    def _item_list(self, fn, n=1, timeout=None, value_data=None,
                   min_score=None, dest=None):
        raw_data = {'n': n}
        if timeout is not None:
            raw_data['timeout'] = timeout
        if min_score is not None:
            raw_data['min_score'] = min_score
        if dest is not None:
            raw_data['dest'] = dest

        items = self._lua(fn, raw_data, value_data)
        if n == 1:
            return self.kt.decode_value(items[b'0']) if items else None

        accum = []
        if items:
            for key in sorted(items, key=int):
                accum.append(self.kt.decode_value(items[key]))
        return accum

    def pop(self, n=1, min_score=None):
        return self._item_list('queue_pop', n, min_score=min_score)
    def rpop(self, n=1, min_score=None):
        return self._item_list('queue_rpop', n, min_score=min_score)

    def bpop(self, timeout=None, min_score=None):
        return self._item_list('queue_bpop', 1, timeout, min_score=min_score)

    def peek(self, n=1, min_score=None):
        return self._item_list('queue_peek', n, min_score=min_score)
    def rpeek(self, n=1, min_score=None):
        return self._item_list('queue_rpeek', n, min_score=min_score)

    def count(self):
        return int(self._lua('queue_size')[b'num'])
    __len__ = count

    def remove(self, data, n=None, min_score=None):
        raw_data = {'n': -1 if n is None else n}
        if min_score is not None:
            raw_data['min_score'] = min_score
        value_data = {'data': data}
        return int(self._lua('queue_remove', raw_data, value_data)[b'num'])

    def rremove(self, data, n=None, min_score=None):
        raw_data = {'n': -1 if n is None else n}
        if min_score is not None:
            raw_data['min_score'] = min_score
        value_data = {'data': data}
        return int(self._lua('queue_rremove', raw_data, value_data)[b'num'])

    def set_priority(self, data, score, n=None):
        raw_data = {'score': score, 'n': -1 if n is None else n}
        value_data = {'data': data}
        return int(self._lua('queue_set_score', raw_data, value_data)[b'num'])

    def transfer(self, dest, n=1):
        if isinstance(dest, Queue): dest = dest._key
        return self._item_list('queue_transfer', n, dest=dest)

    def clear(self):
        return int(self._lua('queue_clear')[b'num'])


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


class Schedule(object):
    def __init__(self, client, key, db=None):
        self.kt = client
        self._key = key
        self._db = client.default_db if db is None else db

    def add(self, item, score=0):
        data = {
            'db': self._db,
            'key': self._key,
            'score': str(score),
            'value': self.kt.encode_value(item)}
        out = self.kt.raw_script('schedule_add', data)
        return out[b'key']

    def read(self, score=None, n=None):
        data = {'db': self._db, 'key': self._key}
        if score is not None:
            data['score'] = str(score)
        if n is not None:
            data['n'] = str(n)
        out = self.kt.raw_script('schedule_read', data)
        return [self.kt.decode_value(out[key])
                for key in sorted(out, key=int)]

    def clear(self):
        keys = self.kt.match_prefix(self._key, db=self._db)
        return self.kt.remove_bulk(keys, db=self._db)

    def count(self):
        return len(self.kt.match_prefix(self._key + '\t', db=self._db))
    __len__ = count

    def items(self, n=None):
        keys = self.kt.match_prefix(self._key + '\t', n, self._db)
        data = self.kt.get_bulk(keys, db=self._db)
        return [data[k] for k in keys]
