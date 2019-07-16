#!/usr/bin/env python

import functools
import os
import pickle
import sys
import threading
import time
import unittest
import warnings

try:
    import msgpack
except ImportError:
    msgpack = None

from ukt import *


class BaseTestCase(unittest.TestCase):
    _server = None
    db = None
    lua_path = os.path.join(os.path.dirname(__file__), 'scripts/')
    server = EmbeddedServer
    server_kwargs = None

    @classmethod
    def setUpClass(cls):
        if cls.server is None:
            return

        if sys.version_info[0] > 2:
            warnings.filterwarnings(action='ignore', message='unclosed',
                                    category=ResourceWarning)

        kwargs = {'quiet': True}
        if cls.server_kwargs:
            kwargs.update(cls.server_kwargs)
        cls._server = cls.server(**kwargs)
        cls._server.run()
        cls.db = cls._server.client

    @classmethod
    def tearDownClass(cls):
        if cls._server is not None:
            cls._server.stop()
            cls.db.close_all()
            cls.db = None

    def tearDown(self):
        if self.db is not None:
            self.db.clear()

    @classmethod
    def get_embedded_server(cls):
        if self.server is None:
            raise NotImplementedError


class KyotoTycoonTests(object):
    def test_basic_operations(self):
        """
        Test operations of the KyotoTycoon client.

        This class wraps two protocol handlers - binary and HTTP protocols. The
        interface exposes a super-set of the methods available, preferring the
        bulk/binary APIs where possible.

        Note: protocols are also tested individually.
        """
        self.assertEqual(len(self.db), 0)

        # Test basic set and get.
        self.assertEqual(self.db.set('k1', 'v1'), 1)
        self.assertEqual(self.db.get('k1'), 'v1')
        self.assertTrue(self.db.get('kx') is None)

        # Test setting bulk data returns records set.
        nkeys = self.db.set_bulk({'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(nkeys, 3)

        # Test getting bulk data returns dict of just existing keys.
        self.assertEqual(self.db.get_bulk(['k1', 'k2', 'k3', 'kx']),
                         {'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})

        # Test removing a record returns number of rows removed.
        self.assertEqual(self.db.remove('k1'), 1)
        self.assertEqual(self.db.remove('k1'), 0)

        self.db['k1'] = 'v1'
        self.assertTrue(self.db.exists('k1'))
        self.assertEqual(self.db.length('k1'), 2)
        self.assertEqual(self.db.remove_bulk(['k1', 'k3', 'kx']), 2)
        self.assertEqual(self.db.remove_bulk([]), 0)
        self.assertEqual(self.db.remove_bulk(['k2']), 1)
        self.assertFalse(self.db.exists('k1'))
        self.assertTrue(self.db.length('k1') is None)

        self.db.append('key', 'abc')
        self.db.append('key', 'def')
        self.assertEqual(self.db['key'], 'abcdef')

        # Test atomic replace and pop.
        self.assertTrue(self.db.replace('key', 'xyz'))
        self.assertEqual(self.db.seize('key'), 'xyz')
        self.assertFalse(self.db.seize('key'))
        self.assertFalse(self.db.replace('key', 'abc'))
        self.assertTrue(self.db.add('key', 'foo'))
        self.assertFalse(self.db.add('key', 'bar'))
        self.assertEqual(self.db['key'], 'foo')

        # Test compare-and-swap.
        self.assertTrue(self.db.cas('key', 'foo', 'baz'))
        self.assertFalse(self.db.cas('key', 'foo', 'bar'))
        self.assertEqual(self.db['key'], 'baz')

        # Test dict interface.
        self.assertTrue('key' in self.db)
        self.assertFalse('other' in self.db)
        self.assertEqual(len(self.db), 1)
        self.assertEqual(self.db.count(), 1)
        self.db['k1'] = 'v1'
        self.db.update({'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(self.db.pop('k1'), 'v1')
        self.assertTrue(self.db.pop('k1') is None)
        self.assertEqual(sorted(list(self.db)), ['k2', 'k3', 'key'])
        del self.db['k3']
        self.assertEqual(sorted(list(self.db.keys())), ['k2', 'key'])
        self.assertEqual(sorted(list(self.db.values())), ['baz', 'v2'])
        self.assertEqual(sorted(list(self.db.items())),
                         [('k2', 'v2'), ('key', 'baz')])

        # Test matching.
        self.assertEqual(sorted(self.db.match_prefix('k')), ['k2', 'key'])
        self.assertEqual(self.db.match_regex('k[0-9]'), ['k2'])
        self.assertEqual(self.db.match_regex('x\d'), [])
        self.assertEqual(self.db.match_similar('k'), ['k2'])
        self.assertEqual(sorted(self.db.match_similar('k', 2)), ['k2', 'key'])

        # Test numeric operations.
        self.assertEqual(self.db.increment('n'), 1)
        self.assertEqual(self.db.increment('n', 3), 4)
        self.assertEqual(self.db.increment_double('nd'), 1.)
        self.assertEqual(self.db.increment_double('nd', 2.5), 3.5)

    def test_noreply(self):
        self.assertTrue(self.db.set('k1', 'v1', no_reply=True) is None)
        self.assertEqual(self.db.get('k1'), 'v1')
        self.assertTrue(self.db.remove('k1', no_reply=True) is None)
        self.assertTrue(self.db.get('k1') is None)

        self.assertTrue(self.db.set_bulk({'k1': 'v1'}, no_reply=True) is None)
        self.assertEqual(self.db.get('k1'), 'v1')
        self.assertTrue(self.db.remove_bulk(['k1'], no_reply=True) is None)
        self.assertTrue(self.db.get('k1') is None)

    def test_get_bytes(self):
        self.db.set('k1', b'v1')
        self.db.set('k2', b'\xff\x00\xff')
        self.assertEqual(self.db.get('k1', decode_value=False), b'v1')
        self.assertEqual(self.db.get('k2', decode_value=False),
                         b'\xff\x00\xff')
        self.assertEqual(self.db.get_bulk(['k1', 'k2'], decode_values=False), {
            'k1': b'v1', 'k2': b'\xff\x00\xff'})

    def test_large_read_write(self):
        long_str = 'a' * (1024 * 1024 * 32)  # 32MB string.
        self.db['key'] = long_str
        self.assertEqual(self.db['key'], long_str)
        del self.db['key']
        self.assertEqual(len(self.db), 0)

    def test_protocol(self):
        # Both protocols support some basic methods, which we will test (namely
        # get/set/remove and their bulk equivalents).
        self.assertEqual(self.db.count(), 0)

        # Test basic set and get.
        self.db.set('k1', 'v1')
        self.assertEqual(self.db.get('k1'), 'v1')
        self.assertTrue(self.db.get('kx') is None)

        # Test setting bulk data returns records set.
        nkeys = self.db.set_bulk({'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(nkeys, 3)

        # Test getting bulk data returns dict of just existing keys.
        self.assertEqual(self.db.get_bulk(['k1', 'k2', 'k3', 'kx']),
                         {'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})

        # Test removing a record returns number of rows removed.
        self.assertEqual(self.db.remove('k1'), 1)
        self.assertEqual(self.db.remove('k1'), 0)

        self.db.set('k1', 'v1')
        self.assertEqual(self.db.remove_bulk(['k1', 'k3', 'kx']), 2)
        self.assertEqual(self.db.remove_bulk([]), 0)
        self.assertEqual(self.db.remove_bulk(['k2']), 1)

    def test_http_protocol_special(self):
        self.db.append('key', 'abc')
        self.db.append('key', 'def')
        self.assertEqual(self.db.get('key'), 'abcdef')

        # Test atomic replace and pop.
        self.assertTrue(self.db.replace('key', 'xyz'))
        self.assertEqual(self.db.seize('key'), 'xyz')
        self.assertFalse(self.db.seize('key'))
        self.assertFalse(self.db.replace('key', 'abc'))
        self.assertTrue(self.db.add('key', 'foo'))
        self.assertFalse(self.db.add('key', 'bar'))
        self.assertEqual(self.db.get('key'), 'foo')

        # Test compare-and-swap.
        self.assertTrue(self.db.cas('key', 'foo', 'baz'))
        self.assertFalse(self.db.cas('key', 'foo', 'bar'))
        self.assertEqual(self.db.get('key'), 'baz')

        self.assertTrue(self.db.check('key'))
        self.assertFalse(self.db.check('other'))
        self.assertEqual(self.db.count(), 1)

        # Test numeric operations.
        self.assertEqual(self.db.increment('n'), 1)
        self.assertEqual(self.db.increment('n', 3), 4)
        self.assertEqual(self.db.increment_double('nd'), 1.)
        self.assertEqual(self.db.increment_double('nd', 2.5), 3.5)

        # Flush db.
        self.db.clear()

        # Set some data for matching tests.
        self.db.set_bulk(dict(('k%04d' % i, 'v%01024d' % i)
                              for i in range(100)), 0)
        keys = ['k%04d' % i for i in range(100)]

        # Test matching.
        self.assertEqual(sorted(self.db.match_prefix('k')), keys)
        self.assertEqual(sorted(self.db.match_regex('k00[25]3')), ['k0023', 'k0053'])
        self.assertEqual(self.db.match_regex('x\d'), [])
        self.assertEqual(self.db.match_similar('k0022'), [
            'k0022',  # Exact match is always first, regardless of storage.
            'k0002', 'k0012',
            'k0020', 'k0021', 'k0023', 'k0024', 'k0025', 'k0026', 'k0027',
            'k0028', 'k0029', 'k0032', 'k0042', 'k0052', 'k0062', 'k0072',
            'k0082', 'k0092'])

    def test_report(self):
        report = self.db.report()
        accum = {}
        for part in report['db_0'].split():
            key, value = part.split(b'=')
            accum[key] = value
        self.assertEqual(accum[b'path'],
                         self.server_kwargs['database'].encode('utf8'))


class TestKyotoTycoonHash(KyotoTycoonTests, BaseTestCase):
    server_kwargs = {'database': '*'}


class TestKyotoTycoonBTree(KyotoTycoonTests, BaseTestCase):
    server_kwargs = {'database': '%'}


class TestKyotoTycoonCursor(BaseTestCase):
    server_kwargs = {'database': '%'}

    def setUp(self):
        super(TestKyotoTycoonCursor, self).setUp()
        self.db.update({'k1': 'v1', 'k2': 'v2', 'k3': 'v3', 'k4': 'v4'})

    def test_multiple_cursors(self):
        c1 = self.db.cursor()
        c2 = self.db.cursor()
        c3 = self.db.cursor()
        self.assertTrue(c1.jump('k1'))
        self.assertTrue(c2.jump('k2'))
        self.assertTrue(c3.jump('k3'))
        self.assertEqual(c1.get(), ('k1', 'v1'))
        self.assertEqual(c2.get(), ('k2', 'v2'))
        self.assertEqual(c3.get(), ('k3', 'v3'))

        self.assertTrue(c1.step())
        self.assertEqual(c1.get(), ('k2', 'v2'))
        self.assertEqual(c1.seize(), ('k2', 'v2'))
        self.assertEqual(c2.get(), ('k3', 'v3'))
        self.assertEqual(c2.seize(), ('k3', 'v3'))
        for c in (c1, c2, c3):
            self.assertEqual(c.get(), ('k4', 'v4'))
        self.assertTrue(c3.remove())
        for c in (c1, c2, c3):
            self.assertTrue(c.get() is None)

        c1.jump()
        self.assertEqual(c1.get(), ('k1', 'v1'))
        self.assertTrue(c1.remove())
        self.assertFalse(c2.jump())

    def test_cursor_movement(self):
        cursor = self.db.cursor()
        self.assertEqual(list(cursor), [('k1', 'v1'), ('k2', 'v2'),
                                        ('k3', 'v3'), ('k4', 'v4')])

        # Jumping in-between moves to closest without going under.
        self.assertTrue(cursor.jump('k1x'))
        self.assertEqual(cursor.key(), 'k2')
        self.assertEqual(cursor.value(), 'v2')

        # Jumping backwards in-between moves to closest while going over.
        self.assertTrue(cursor.jump_back('k2x'))
        self.assertEqual(cursor.key(), 'k2')
        self.assertEqual(cursor.value(), 'v2')

        # We cannot jump past the last record, but we can jump below the first.
        # Similarly, we can't step_back prior to the first record.
        self.assertFalse(cursor.jump('k5'))
        self.assertTrue(cursor.jump('k0'))
        self.assertEqual(cursor.key(), 'k1')
        self.assertFalse(cursor.step_back())

        # We cannot jump_back prior to the first record, but we can jump_back
        # from after the last. Similarly, we can't step past the last record.
        self.assertFalse(cursor.jump_back('k0'))
        self.assertTrue(cursor.jump_back('k5'))
        self.assertEqual(cursor.key(), 'k4')
        self.assertFalse(cursor.step())

    def test_cursor_write(self):
        cursor = self.db.cursor()
        cursor.jump('k2')

        self.assertTrue(cursor.set_value('v2-x'))
        self.assertEqual(cursor.get(), ('k2', 'v2-x'))
        self.assertEqual(self.db['k2'], 'v2-x')
        self.assertTrue(cursor.remove())
        self.assertEqual(cursor.get(), ('k3', 'v3'))
        self.assertFalse('k2' in self.db)
        self.assertTrue(cursor.step_back())
        self.assertEqual(cursor.get(), ('k1', 'v1'))

        self.assertEqual(cursor.seize(), ('k1', 'v1'))
        self.assertTrue(cursor.seize() is None)
        self.assertFalse(cursor.is_valid())

        self.assertTrue(cursor.jump())
        self.assertEqual(cursor.seize(), ('k3', 'v3'))
        self.assertTrue(cursor.jump_back())
        self.assertEqual(cursor.get(), ('k4', 'v4'))

        self.assertEqual(list(cursor), [('k4', 'v4')])
        self.assertEqual(list(cursor), [('k4', 'v4')])
        self.assertTrue(cursor.jump_back())
        self.assertTrue(cursor.remove())
        self.assertEqual(list(cursor), [])

    def test_implicit_cursor_operations(self):
        self.assertEqual(list(self.db.keys()), ['k1', 'k2', 'k3', 'k4'])
        self.assertEqual(list(self.db.values()), ['v1', 'v2', 'v3', 'v4'])
        self.assertEqual(list(self.db.items()), [
            ('k1', 'v1'),
            ('k2', 'v2'),
            ('k3', 'v3'),
            ('k4', 'v4')])

        # Nonlazy.
        self.assertEqual(self.db.keys_nonlazy(), ['k1', 'k2', 'k3', 'k4'])


class TestKyotoTycoonSerializers(BaseTestCase):
    server_kwargs = {'database': '*'}

    def get_client(self, serializer):
        return KyotoTycoon(self._server.host, self._server.port,
                           serializer=serializer)

    def test_serializer_binary(self):
        db = self.get_client(KT_BINARY)
        db.set('k1', 'v1')
        db.set('k2', b'\xe1\x80\x80')
        self.assertEqual(db.get('k1'), 'v1')
        self.assertEqual(db.get('k2'), u'\u1000')
        self.assertEqual(db.get_bulk(['k1', 'k2']),
                         {'k1': 'v1', 'k2': u'\u1000'})

    def _test_serializer_object(self, serializer):
        db = self.get_client(serializer)

        obj = {'w': {'wk': 'wv'}, 'x': 0, 'y': ['aa', 'bb'], 'z': None}
        db.set('k1', obj)
        self.assertEqual(db.get('k1'), obj)

        db.set('k2', '')
        self.assertEqual(db.get('k2'), '')

        self.assertEqual(db.get_bulk(['k1', 'k2']), {'k1': obj, 'k2': ''})

    def test_serializer_json(self):
        self._test_serializer_object(KT_JSON)

    def test_serializer_pickle(self):
        self._test_serializer_object(KT_PICKLE)

    def test_serializer_none(self):
        db = self.get_client(KT_NONE)
        db.set('k1', b'v1')
        self.assertEqual(self.db.get('k1'), 'v1')

        db[b'k2'] = b'v2'
        self.assertEqual(self.db.get_bulk([b'k1', b'k2']),
                         {'k1': 'v1', 'k2': 'v2'})

    @unittest.skipIf(msgpack is None, 'msgpack-python not installed')
    def test_serializer_msgpack(self):
        db = self.get_client(KT_MSGPACK)

        obj = {'w': {'wk': 'wv'}, 'x': 0, 'y': ['aa', 'bb'], b'z': None}
        db.set('k1', obj)
        self.assertEqual(db.get('k1'), {'w': {'wk': 'wv'}, 'x': 0,
                                        'y': ['aa', 'bb'], b'z': None})

        db.set('k2', '')
        self.assertEqual(db.get('k2'), '')

        db.set('k3', [u'foo', b'bar'])
        self.assertEqual(db.get('k3'), [u'foo', b'bar'])


class TestKyotoTycoonScripting(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {
        'database': '%',
        'server_args': ['-scr', lua_script]}

    def test_script_set(self):
        L = self.db.lua

        # Test adding a single item.
        self.assertEqual(L.sadd(key='s1', value='foo'), {'num': '1'})
        self.assertEqual(L.sadd(key='s1', value='foo'), {'num': '0'})

        # Test adding multiple items.
        items = b'\x01'.join([b'bar', b'baz', b'nug'])
        self.assertEqual(L.sadd(key='s1', value=items), {'num': '3'})

        # Test get cardinality.
        self.assertEqual(L.scard(key='s1'), {'num': '4'})

        # Test membership.
        self.assertEqual(L.sismember(key='s1', value='bar'), {'num': '1'})
        self.assertEqual(L.sismember(key='s1', value='baze'), {'num': '0'})

        keys = ['bar', 'baz', 'foo', 'nug']

        # Test get members.
        self.assertEqual(L.smembers(key='s1'), dict((k, '1') for k in keys))
        self.assertEqual(L.scard(key='s1'), {'num': '4'})

        # Test pop.
        res = L.spop(key='s1')
        self.assertEqual(res['num'], '1')
        self.assertTrue(res['value'] in keys)
        self.assertEqual(L.scard(key='s1'), {'num': '3'})

        # Pop remaining 3 items.
        for _ in range(3):
            res = L.spop(key='s1')
            self.assertTrue(res['value'] in keys)

        self.assertEqual(L.scard(key='s1'), {'num': '0'})
        res = L.spop(key='s1')
        self.assertEqual(res, {'num': '0'})

        # Restore all keys.
        L.sadd(key='s1', value=b'\x01'.join(k.encode() for k in keys))
        self.assertEqual(L.srem(key='s1', value='nug'), {'num': '1'})
        self.assertEqual(L.srem(key='s1', value='nug'), {'num': '0'})

        # Create another set, s2 {baze, foo, zai}.
        L.sadd(key='s2', value=b'\x01'.join([b'baze', b'foo', b'zai']))

        # Test multiple set operations, {bar, baz, foo} | {baze, foo, zai}.
        self.assertEqual(L.sinter(key1='s1', key2='s2'), {'foo': '1'})
        res = L.sunion(key1='s1', key2='s2')
        self.assertEqual(res, dict((k, '1') for k in
                                   ('bar', 'baz', 'baze', 'foo', 'zai')))

        res = L.sdiff(key1='s1', key2='s2')
        self.assertEqual(res, {'bar': '1', 'baz': '1'})
        res = L.sdiff(key1='s2', key2='s1')
        self.assertEqual(res, {'baze': '1', 'zai': '1'})

        res = L.sdiff(key1='s1', key2='s2', dest='s3')
        self.assertEqual(res, {'bar': '1', 'baz': '1'})
        res = L.smembers(key='s3')
        self.assertEqual(res, {'bar': '1', 'baz': '1'})

    def test_script_list(self):
        L = self.db.lua

        self.assertEqual(L.lrpush(key='l1', value='i0'), {})
        # Test appending items to list.
        for i in range(1, 5):
            L.lrpush(key='l1', value='i%s' % i)

        # Test accessing items by index.
        for i in range(5):
            self.assertEqual(L.lindex(key='l1', index=i), {'value': 'i%s' % i})

        # Invalid index returns empty result set.
        self.assertEqual(L.lindex(key='l1', index=6), {})
        self.assertEqual(L.lindex(key='l1', index=-1), {'value': 'i4'})

        # Get length of list, pop last item, verify length change.
        self.assertEqual(L.llen(key='l1'), {'num': '5'})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'i4'})
        self.assertEqual(L.llen(key='l1'), {'num': '4'})

        # Verify setting indices.
        self.assertEqual(L.lset(key='l1', index=2, value='i2-x'), {})
        self.assertEqual(L.lindex(key='l1', index=2), {'value': 'i2-x'})

        self.assertEqual(L.lrpop(key='l1'), {'value': 'i3'})
        self.assertEqual(L.llpop(key='l1'), {'value': 'i0'})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'i2-x'})
        self.assertEqual(L.llpop(key='l1'), {'value': 'i1'})

        self.assertEqual(L.llen(key='l1'), {'num': '0'})
        self.assertEqual(L.llpop(key='l1'), {})
        self.assertEqual(L.lrpop(key='l1'), {})

    def test_list_insert(self):
        # Test getting ranges.
        L = self.db.lua
        for i in range(5):
            L.lrpush(key='l1', value='i%s' % i)

        R = functools.partial(L.lrange, key='l1')
        L.linsert(key='l1', index=1, value='i0.5')
        self.assertEqual(R(start=0, stop=3), {'0': 'i0', '1': 'i0.5',
                                              '2': 'i1'})

        L.linsert(key='l1', index=-1, value='i3.5')
        self.assertEqual(R(), {'0': 'i0', '1': 'i0.5', '2': 'i1', '3': 'i2',
                               '4': 'i3', '5': 'i3.5', '6': 'i4'})

    def test_script_list_ranges(self):
        # Test getting ranges.
        L = self.db.lua
        for i in range(5):
            L.lrpush(key='l1', value='i%s' % i)

        R = functools.partial(L.lrange, key='l1')
        all_items = dict((str(i), 'i%s' % i) for i in range(5))
        self.assertEqual(R(), all_items)
        self.assertEqual(R(start=0), all_items)
        self.assertEqual(R(start=-5), all_items)
        self.assertEqual(R(stop=5), all_items)

        # Within bounds.
        self.assertEqual(R(start=1, stop=4), {'1': 'i1', '2': 'i2', '3': 'i3'})
        self.assertEqual(R(start=0, stop=1), {'0': 'i0'})
        self.assertEqual(R(start=3), {'3': 'i3', '4': 'i4'})
        self.assertEqual(R(stop=-3), {'0': 'i0', '1': 'i1'})
        self.assertEqual(R(start=1, stop=-3), {'1': 'i1'})
        self.assertEqual(R(start=3, stop=-1), {'3': 'i3'})
        self.assertEqual(R(start=-1), {'4': 'i4'})
        self.assertEqual(R(start=-2), {'3': 'i3', '4': 'i4'})

        # Out-of-bounds or out-of-order.
        self.assertEqual(R(start=5), {})
        self.assertEqual(R(start=-6), {})
        self.assertEqual(R(start=0, stop=0), {})
        self.assertEqual(R(start=-1, stop=3), {})
        self.assertEqual(R(start=3, stop=2), {})
        self.assertEqual(R(start=1, stop=1), {})

    def test_script_hash(self):
        L = self.db.lua

        # Set multiple items, returns number set.
        res = L.hmset(table_key='h1', k1='v1', k2='v2', k3='v3')
        self.assertEqual(res['num'], '3')

        # Set individual item using key=..., value=...
        res = L.hset(table_key='h1', key='k1', value='v1-x')
        self.assertEqual(res['num'], '1')

        # Retrieve an individual item.
        self.assertEqual(L.hget(table_key='h1', key='k1'), {'value': 'v1-x'})

        # Missing key returns empty response.
        self.assertEqual(L.hget(table_key='h1', key='kx'), {})

        # Retrieve multiple items. Missing keys are omitted.
        res = L.hmget(table_key='h1', k1='', k2='', kx='')
        self.assertEqual(res, {'k1': 'v1-x', 'k2': 'v2'})

        # Retrieve all key/values in hash.
        res = L.hgetall(table_key='h1')
        self.assertEqual(res, {'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})

        # Delete individual key, returns number deleted.
        self.assertEqual(L.hdel(table_key='h1', key='k2'), {'num': '1'})
        self.assertEqual(L.hdel(table_key='h1', key='k2'), {'num': '0'})

        # Delete multiple keys, returns number deleted.
        self.assertEqual(L.hmdel(table_key='h1', k1='', k3=''), {'num': '2'})
        self.assertEqual(L.hgetall(table_key='h1'), {})

        # We can conditionally set a key (if it does not exist). Returns 1 if
        # successful.
        res = L.hsetnx(table_key='h1', key='k1', value='v1-y')
        self.assertEqual(res, {'num': '1'})

        res = L.hsetnx(table_key='h1', key='k1', value='v1-z')
        self.assertEqual(res, {'num': '0'})

        # Set an additional key and verify hash contents for subsequent checks.
        L.hsetnx(table_key='h1', key='k2', value='v2')
        self.assertEqual(L.hgetall(table_key='h1'), {'k1': 'v1-y', 'k2': 'v2'})

        self.assertEqual(L.hlen(table_key='h1'), {'num': '2'})
        self.assertEqual(L.hcontains(table_key='h1', key='k1'), {'num': '1'})
        self.assertEqual(L.hcontains(table_key='h1', key='kx'), {'num': '0'})

        # Getting values from a non-existent hash returns empty response.
        self.assertEqual(L.hgetall(table_key='h2'), {})

    def test_script_list_items(self):
        self.assertEqual(self.db.script('list'), {})

        self.db.update(k1='v1', k2='v2', k3='v3')
        self.assertEqual(self.db.script('list'),
                         {'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})

    def test_script_get_range(self):
        self.assertEqual(self.db.script('get_range'), {})

        data = {'k%s' % i: 'v%s' % i for i in range(11)}
        self.db.set_bulk(data)

        def assertRange(start, stop, expected):
            params = {}
            if start: params['start'] = start
            if stop: params['stop'] = stop
            self.assertEqual(self.db.script('get_range', params), expected)

        assertRange('k8', None, {'k8': 'v8', 'k9': 'v9'})
        assertRange('k80', None, {'k9': 'v9'})
        assertRange(None, 'k2', {'k0': 'v0', 'k1': 'v1', 'k10': 'v10',
                                 'k2': 'v2'})
        assertRange(None, 'k2.2', self.db.script('get_range', {'stop': 'k2'}))
        assertRange('k10', 'k3', {'k10': 'v10', 'k2': 'v2', 'k3': 'v3'})
        assertRange('k101', 'k3', {'k2': 'v2', 'k3': 'v3'})
        assertRange('k10', 'k31', {'k10': 'v10', 'k2': 'v2', 'k3': 'v3'})
        assertRange('a', 'k1', {'k0': 'v0', 'k1': 'v1'})
        assertRange('k9', 'z', {'k9': 'v9'})
        assertRange('a', 'b', {})
        assertRange('x', 'y', {})
        assertRange('x', None, {})
        assertRange(None, 'a', {})

    def test_get_part(self):
        V = '0123456789'
        self.db.update(k1=V, k2='')

        def assertPart(key, start, stop, expected):
            params = {'key': key, 'start': start}
            if stop is not None:
                params['stop'] = stop
            result = self.db.script('get_part', params)
            if expected is None:
                self.assertTrue('value' not in result)
            else:
                self.assertEqual(result['value'], expected)

        assertPart('k1', 0, None, V)
        assertPart('k1', 0, -1, V[0:-1])
        assertPart('k1', 1, 3, V[1:3])
        assertPart('k1', 1, 30, V[1:])
        assertPart('k1', 20, 30, '')
        assertPart('k1', -3, None, V[-3:])
        assertPart('k1', -5, -1, V[-5:-1])
        assertPart('k1', -20, -10, '')
        assertPart('k1', -20, None, V[-20:])

        assertPart('k2', 0, None, '')
        assertPart('k2', 1, -1, '')
        assertPart('k2', -1, None, '')

        assertPart('k3', 0, None, None)
        assertPart('k3', 1, -1, None)

    def test_queue_methods(self):
        L = self.db.lua
        for i in range(5):
            L.queue_add(queue='tq', data='item-%s' % i)

        self.assertEqual(L.queue_size(queue='tq'), {'num': '5'})

        # By default one item is dequeued.
        result = L.queue_pop(queue='tq')
        self.assertEqual(result, {'0': 'item-0'})
        self.assertEqual(L.queue_size(queue='tq'), {'num': '4'})

        # We can also peek at items.
        self.assertEqual(L.queue_peek(queue='tq'), {'0': 'item-1'})
        self.assertEqual(L.queue_peek(queue='tq', n=2),
                         {'0': 'item-1', '1': 'item-2'})

        # We can dequeue multiple items.
        result = L.queue_pop(queue='tq', n=3)
        self.assertEqual(result, {'0': 'item-1', '1': 'item-2', '2': 'item-3'})

        # Peek when fewer items exist:
        self.assertEqual(L.queue_peek(queue='tq', n=3), {'0': 'item-4'})

        # It's OK to pop if fewer items exist.
        result = L.queue_pop(queue='tq', n=3)
        self.assertEqual(result, {'0': 'item-4'})

        # No items -> empty string and zero count.
        self.assertEqual(L.queue_pop(queue='tq'), {})
        self.assertEqual(L.queue_peek(queue='tq'), {})
        self.assertEqual(L.queue_size(queue='tq'), {'num': '0'})

        L.queue_add(queue='tq', data='item-y')
        L.queue_add(queue='tq', data='item-z')
        self.assertEqual(L.queue_clear(queue='tq'), {'num': '2'})
        self.assertEqual(L.queue_clear(queue='tq'), {'num': '0'})

        for i in range(6):
            L.queue_add(queue='tq', data='item-%s' % i)

        # Reverse-peek.
        self.assertEqual(L.queue_rpeek(queue='tq'), {'0': 'item-5'})
        self.assertEqual(L.queue_rpeek(queue='tq', n=2),
                         {'0': 'item-5', '1': 'item-4'})

        # Reverse-pop.
        result = L.queue_rpop(queue='tq', n=2)
        self.assertEqual(result, {'0': 'item-5', '1': 'item-4'})
        self.assertEqual(L.queue_pop(queue='tq'), {'0': 'item-0'})
        self.assertEqual(L.queue_peek(queue='tq'), {'0': 'item-1'})
        self.assertEqual(L.queue_rpop(queue='tq'), {'0': 'item-3'})
        self.assertEqual(L.queue_rpeek(queue='tq'), {'0': 'item-2'})

        # We can request more items than exist with rpeek.
        self.assertEqual(L.queue_rpeek(queue='tq', n=4),
                         {'0': 'item-2', '1': 'item-1'})

        # We can attempt to reverse-pop more items than exist:
        result = L.queue_rpop(queue='tq', n=4)
        self.assertEqual(result, {'0': 'item-2', '1': 'item-1'})
        self.assertEqual(L.queue_rpop(queue='tq'), {})
        self.assertEqual(L.queue_pop(queue='tq'), {})

        # Test loop termination logic when we have no keys in the db.
        self.db.clear()
        self.assertEqual(L.queue_rpop(queue='tq'), {})
        self.assertEqual(L.queue_pop(queue='tq'), {})

        # Test bulk-add feature.
        data = {str(i): 'i%s' % (i % 2) for i in range(5)}
        self.assertEqual(L.queue_madd(queue='tq', **data), {'num': '5'})
        self.assertEqual(L.queue_peek(queue='tq', n=5), {
            '0': 'i0', '1': 'i1', '2': 'i0', '3': 'i1', '4': 'i0'})

        # Verify we can remove data by value.
        self.assertEqual(L.queue_remove(queue='tq', data='i1'), {'num': '2'})
        self.assertEqual(L.queue_remove(queue='tq', data='x'), {'num': '0'})
        self.assertEqual(L.queue_size(queue='tq'), {'num': '3'})

        # We can specify a limit on the number of items removed.
        self.assertEqual(L.queue_remove(queue='tq', data='i0', n=2),
                         {'num': '2'})
        self.assertEqual(L.queue_size(queue='tq'), {'num': '1'})
        self.assertEqual(L.queue_pop(queue='tq'), {'0': 'i0'})

        # Verify remove-by-value, reverse.
        for i in range(10):
            # i0, i1, i2, i0, i1, i2, i0, i1, i2, i0
            L.queue_add(queue='tq', data='i%s' % (i % 3))

        self.assertEqual(L.queue_rremove(queue='tq', data='i0', n=3),
                         {'num': '3'})
        self.assertEqual(L.queue_peek(queue='tq', n=10), {
            '0': 'i0', '1': 'i1', '2': 'i2', '3': 'i1', '4': 'i2',
            '5': 'i1', '6': 'i2'})
        self.assertEqual(L.queue_rremove(queue='tq', data='i1', n=2),
                         {'num': '2'})
        self.assertEqual(L.queue_peek(queue='tq', n=10), {
            '0': 'i0', '1': 'i1', '2': 'i2', '3': 'i2', '4': 'i2'})
        self.assertEqual(L.queue_clear(queue='tq'), {'num': '5'})

    def test_queue_helper(self):
        qa = Queue(self.db, 'qa')
        qb = Queue(self.db, 'qb')

        for i in range(20):
            qa.add('i%s' % i)
            qb.add('i%s' % (i % 4))

        self.assertEqual(len(qa), 20)
        self.assertEqual(len(qb), 20)

        self.assertEqual(qa.pop(), b'i0')
        self.assertEqual(qa.rpop(), b'i19')
        self.assertEqual(qa.pop(n=3), [b'i1', b'i2', b'i3'])
        self.assertEqual(qa.rpop(n=3), [b'i18', b'i17', b'i16'])
        self.assertEqual(qa.peek(n=3), [b'i4', b'i5', b'i6'])
        self.assertEqual(qa.rpeek(n=3), [b'i15', b'i14', b'i13'])

        # i0, i1, i2, i3 ... x5.
        self.assertEqual(qb.remove('i1', n=4), 4)
        self.assertEqual(qb.rremove('i2', n=4), 4)
        self.assertEqual(len(qb), 12)
        self.assertEqual(qb.peek(20), [b'i0', b'i2', b'i3', b'i0', b'i3',
                                       b'i0', b'i3', b'i0', b'i3', b'i0',
                                       b'i1', b'i3'])
        self.assertEqual(qb.remove('i3', n=5), 5)
        self.assertEqual(qb.remove('i0', n=10), 5)
        self.assertEqual(qb.pop(), b'i2')
        self.assertEqual(qb.pop(), b'i1')
        self.assertEqual(len(qb), 0)

        self.assertEqual(qa.remove('i7'), 1)
        self.assertEqual(qa.remove('i7'), 0)
        self.assertEqual(qa.pop(n=5), [b'i4', b'i5', b'i6', b'i8', b'i9'])

    def test_hexastore(self):
        L = self.db.lua
        data = (
            ('charlie', 'likes', 'zaizee'),
            ('charlie', 'likes', 'huey'),
            ('charlie', 'likes', 'mickey'),
            ('huey', 'likes', 'zaizee'),
            ('zaizee', 'likes', 'huey'),
        )
        for s, p, o in data:
            L.hx_add(s=s, p=p, o=o)

        self.assertEqual(self.db.count(), 15)  # 5 * 3.
        data = L.hx_query(s='charlie', p='likes')
        self.assertEqual(data, {'o0': 'huey', 'o1': 'mickey', 'o2': 'zaizee'})

        L.hx_remove(s='charlie', p='likes', o='mickey')
        data = L.hx_query(s='charlie', p='likes')
        self.assertEqual(data, {'o0': 'huey', 'o1': 'zaizee'})

        data = L.hx_query(o='zaizee')
        self.assertEqual(data, {
            's0': 'charlie', 'p0': 'likes',
            's1': 'huey', 'p1': 'likes'})
        self.db.clear()

    def test_python_list_integration(self):
        L = self.db.lua
        data = ['foo', 'a' * 1024, '', 'b' * 1024 * 32, 'c']

        self.db['l1'] = self.db.serialize_list(data)
        self.assertEqual(L.llen(key='l1'), {'num': '5'})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'c'})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'b' * 1024 * 32})
        self.assertEqual(L.lrpop(key='l1'), {'value': ''})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'a' * 1024})
        self.assertEqual(L.lrpop(key='l1'), {'value': 'foo'})

        for item in data:
            L.lrpush(key='l1', value=item)

        raw_data = self.db.get_bytes('l1')
        self.assertEqual(self.db.deserialize_list(raw_data), data)
        self.assertEqual(L.lrange(key='l1'), dict((str(i), data[i])
                                                  for i in range(len(data))))

        db2 = KyotoTycoon(port=self.db.port, serializer=KT_NONE)
        db2.set('l2', self.db.serialize_list(['i0', 'i1', 'i2', 'i3']))
        self.assertEqual(L.llen(key='l2'), {'num': '4'})
        self.assertEqual(L.lrpop(key='l2'), {'value': 'i3'})
        self.assertEqual(self.db.deserialize_list(db2.get('l2')),
                         ['i0', 'i1', 'i2'])
        db2.close_all()

    def test_python_dict_integration(self):
        L = self.db.lua
        data = {'a' * 64: 'b' * 128, 'c' * 1024: 'd' * 1024 * 32,
                'e' * 256: 'f' * 1024 * 1024, 'g': ''}

        self.db['h1'] = self.db.serialize_dict(data)
        self.assertEqual(L.hgetall(table_key='h1'), data)
        self.assertEqual(L.hget(table_key='h1', key='e' * 256),
                         {'value': 'f' * 1024 * 1024})
        self.assertTrue(L.hcontains(table_key='h1', key='a' * 64))
        del self.db['h1']

        L.hmset(table_key='h1', **data)
        raw_data = self.db.get_bytes('h1')
        self.assertEqual(self.db.deserialize_dict(raw_data), data)
        self.assertEqual(L.hgetall(table_key='h1'), data)

        db2 = KyotoTycoon(port=self.db.port, serializer=KT_NONE)

        data = self.db.serialize_dict({'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})
        db2.set('h2', data)
        self.assertEqual(L.hdel(table_key='h2', key='k2'), {'num': '1'})
        self.assertEqual(L.hgetall(table_key='h2'), {'k1': 'v1', 'k3': 'v3'})
        self.assertEqual(self.db.deserialize_dict(db2.get('h2')),
                         {'k1': 'v1', 'k3': 'v3'})
        db2.close_all()


class TestKyotoTycoonScriptingSerialization(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {
        'serializer': KT_PICKLE,
        'database': '%',
        'server_args': ['-scr', lua_script]}

    def test_queue_pickle(self):
        q = Queue(self.db, 'queue')
        data = [{'item': 'i%s' % i} for i in range(3)]
        serialized = [pickle.dumps(item) for item in data]
        q.add(serialized[0])
        q.extend(serialized[1:])

        self.assertEqual(pickle.loads(q.pop()), {'item': 'i0'})
        vals = [pickle.loads(i) for i in q.rpop(2)]
        self.assertEqual(vals, [{'item': 'i2'}, {'item': 'i1'}])


class TestKyotoTycoonScriptingMultiDB(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {'database': '%', 'server_args': ['-scr', lua_script, '%']}

    def test_script_multi_db(self):
        self.db.clear(db=0)
        self.db.clear(db=1)

        for i in range(3):
            self.db.set('k%s' % i, 'v%s' % i, db=(i % 2))

        self.assertEqual(self.db.lua.list(), {'k0': 'v0', 'k2': 'v2'})
        self.assertEqual(self.db.lua.list(db=0), {'k0': 'v0', 'k2': 'v2'})
        self.assertEqual(self.db.lua.list(db=1), {'k1': 'v1'})

    def test_script_datatypes_multi_db(self):
        L = self.db.lua

        # Test sets with multiple dbs.
        for i in range(5):
            L.sadd(key='s1', value='v%s' % i, db=(i % 2))

        self.assertEqual(L.scard(key='s1', db=0), {'num': '3'})
        self.assertEqual(L.scard(key='s1', db=1), {'num': '2'})

        # By default the database is 0.
        self.assertEqual(sorted(L.smembers(key='s1')), ['v0', 'v2', 'v4'])
        self.assertEqual(sorted(L.smembers(key='s1', db=0)),
                         ['v0', 'v2', 'v4'])
        self.assertEqual(sorted(L.smembers(key='s1', db=1)), ['v1', 'v3'])

        self.assertEqual(L.sismember(key='s1', value='v2', db=0), {'num': '1'})
        self.assertEqual(L.sismember(key='s1', value='v2', db=1), {'num': '0'})
        self.assertEqual(L.sismember(key='s1', value='v1', db=0), {'num': '0'})
        self.assertEqual(L.sismember(key='s1', value='v1', db=1), {'num': '1'})

        self.assertTrue(L.spop(key='s1')['value'] in ['v0', 'v2', 'v4'])
        self.assertTrue(L.spop(key='s1', db=1)['value'] in ['v1', 'v3'])

        # Test hashes with multiple dbs.
        L.hmset(table_key='h1', k1='v1', k2='v2', db=0)
        L.hmset(table_key='h1', k1='v1x', k2='v2x', db=1)

        L.hset(table_key='h1', key='k1', value='v1z', db=0)
        L.hset(table_key='h1', key='k1', value='v1y', db=1)

        self.assertEqual(L.hgetall(table_key='h1'), {'k1': 'v1z', 'k2': 'v2'})
        self.assertEqual(L.hgetall(table_key='h1', db=0),
                         {'k1': 'v1z', 'k2': 'v2'})
        self.assertEqual(L.hgetall(table_key='h1', db=1),
                         {'k1': 'v1y', 'k2': 'v2x'})

        # Test lists with multiple dbs.
        for i in range(5):
            L.llpush(key='l1', value='i%s' % i, db=(i % 2))

        self.assertEqual(L.llen(key='l1')['num'], '3')
        self.assertEqual(L.llen(key='l1', db=0)['num'], '3')
        self.assertEqual(L.llen(key='l1', db=1)['num'], '2')

        self.assertEqual(L.llpop(key='l1')['value'], 'i4')
        self.assertEqual(L.lrpop(key='l1', db=0)['value'], 'i0')
        self.assertEqual(L.llpop(key='l1', db=1)['value'], 'i3')
        self.assertEqual(L.lrpop(key='l1', db=1)['value'], 'i1')


class TestKyotoTycoonMultiDatabase(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {'database': '%', 'server_args': ['-scr', lua_script, '*']}

    def tearDown(self):
        super(TestKyotoTycoonMultiDatabase, self).tearDown()
        self.db.clear(0)
        self.db.clear(1)

    def test_multiple_databases_present(self):
        report = self.db.report()
        self.assertTrue('db_0' in report)
        self.assertTrue('db_1' in report)
        self.assertTrue(report['db_0'].endswith(b'path=*'))
        self.assertTrue(report['db_1'].endswith(b'path=%'))

    def test_multiple_databases_lua(self):
        db = KyotoTycoon(self._server.host, self._server.port,
                         serializer=KT_NONE)

        db.set_bulk({'k1': 'v1-0', 'k2': 'v2-0', 'k3': 'v3-0'}, db=0)
        db.set_bulk({'k1': 'v1-1', 'k2': 'v2-1', 'k3': 'v3-1'}, db=1)

        L = db.lua
        self.assertEqual(L.list(), L.list(db=0, encode_values=False))
        self.assertEqual(L.list(db=0, encode_values=False), {
            'k1': b'v1-0',
            'k2': b'v2-0',
            'k3': b'v3-0'})
        self.assertEqual(L.list(db=1, encode_values=False), {
            'k1': b'v1-1',
            'k2': b'v2-1',
            'k3': b'v3-1'})

    def test_multiple_databases(self):
        k0 = KyotoTycoon(self._server.host, self._server.port, default_db=0)
        k1 = KyotoTycoon(self._server.host, self._server.port, default_db=1)

        k0.set('k1', 'v1-0')
        k0.set('k2', 'v2-0')
        self.assertEqual(len(k0), 2)
        self.assertEqual(len(k1), 0)

        k1.set('k1', 'v1-1')
        k1.set('k2', 'v2-1')
        self.assertEqual(len(k0), 2)
        self.assertEqual(len(k1), 2)

        self.assertEqual(k0.get('k1'), 'v1-0')
        k0.remove('k1')
        self.assertTrue(k0.get('k1') is None)

        self.assertEqual(k1.get('k1'), 'v1-1')
        k1.remove('k1')
        self.assertTrue(k1.get('k1') is None)

        k0.set_bulk({'k1': 'v1-0', 'k3': 'v3-0'})
        k1.set_bulk({'k1': 'v1-1', 'k3': 'v3-1'})

        self.assertEqual(k0.get_bulk(['k1', 'k2', 'k3']),
                         {'k1': 'v1-0', 'k2': 'v2-0', 'k3': 'v3-0'})
        self.assertEqual(k1.get_bulk(['k1', 'k2', 'k3']),
                         {'k1': 'v1-1', 'k2': 'v2-1', 'k3': 'v3-1'})

        self.assertEqual(k0.remove_bulk(['k3', 'k2']), 2)
        self.assertEqual(k0.remove_bulk(['k3', 'k2']), 0)
        self.assertEqual(k1.remove_bulk(['k3', 'k2']), 2)
        self.assertEqual(k1.remove_bulk(['k3', 'k2']), 0)

        self.assertTrue(k0.add('k2', 'v2-0'))
        self.assertFalse(k0.add('k2', 'v2-x'))

        self.assertTrue(k1.add('k2', 'v2-1'))
        self.assertFalse(k1.add('k2', 'v2-x'))

        self.assertEqual(k0['k2'], 'v2-0')
        self.assertEqual(k1['k2'], 'v2-1')

        self.assertTrue(k0.replace('k2', 'v2-0x'))
        self.assertFalse(k0.replace('k3', 'v3-0'))
        self.assertTrue(k1.replace('k2', 'v2-1x'))
        self.assertFalse(k1.replace('k3', 'v3-1'))

        self.assertEqual(k0['k2'], 'v2-0x')
        self.assertEqual(k1['k2'], 'v2-1x')

        self.assertTrue(k0.append('k3', 'v3-0'))
        self.assertTrue(k0.append('k3', 'x'))
        self.assertTrue(k1.append('k3', 'v3-1'))
        self.assertTrue(k1.append('k3', 'x'))

        self.assertEqual(k0['k3'], 'v3-0x')
        self.assertEqual(k1['k3'], 'v3-1x')

        for k in (k0, k1):
            self.assertTrue(k.exists('k3'))
            self.assertEqual(k.length('k3'), 5)
            self.assertEqual(k.remove('k3'), 1)
            self.assertFalse(k.exists('k3'))

        self.assertEqual(k0.seize('k2'), 'v2-0x')
        self.assertEqual(k1.seize('k2'), 'v2-1x')

        self.assertTrue(k0.cas('k1', 'v1-0', 'v1-0x'))
        self.assertFalse(k0.cas('k1', 'v1-0', 'v1-0z'))

        self.assertTrue(k1.cas('k1', 'v1-1', 'v1-1x'))
        self.assertFalse(k1.cas('k1', 'v1-1', 'v1-1z'))

        self.assertEqual(k0['k1'], 'v1-0x')
        self.assertEqual(k1['k1'], 'v1-1x')

        for k in (k0, k1):
            k.remove_bulk(['i', 'j'])
            self.assertEqual(k.increment('i'), 1)
            self.assertEqual(k.increment('i'), 2)

            self.assertEqual(k.increment_double('j'), 1.)
            self.assertEqual(k.increment_double('j'), 2.)

        self.assertEqual(k0['k1'], 'v1-0x')
        self.assertEqual(k0['k1', 1], 'v1-1x')
        self.assertEqual(k1['k1'], 'v1-1x')
        self.assertEqual(k1['k1', 0], 'v1-0x')

        k0['k2'] = 'v2-0y'
        k0['k2', 1] = 'v2-1y'
        self.assertEqual(k0.get('k2'), 'v2-0y')
        self.assertEqual(k1.get('k2'), 'v2-1y')
        k1['k2'] = 'v2-1z'
        k1['k2', 0] = 'v2-0z'
        self.assertEqual(k0.get('k2'), 'v2-0z')
        self.assertEqual(k1.get('k2'), 'v2-1z')

        del k0['k1']
        del k0['k1', 1]
        self.assertTrue(k0['k1'] is None)
        self.assertTrue(k1['k1'] is None)
        del k1['k2']
        del k1['k2', 0]
        self.assertTrue(k0['k2'] is None)
        self.assertTrue(k1['k2'] is None)

        k0['k3'] = 'v3-0'
        k0['k03'] = 'v03'
        k1['k3'] = 'v3-1'
        k1['k13'] = 'v13'
        self.assertTrue('k3' in k0)
        self.assertTrue('k03' in k0)
        self.assertTrue('k13' not in k0)
        self.assertTrue('k3' in k1)
        self.assertTrue('k13' in k1)
        self.assertTrue('k03' not in k1)

        self.assertEqual(sorted(k0.match_prefix('k')), ['k03', 'k3'])
        self.assertEqual(sorted(k0.match_prefix('k', db=1)), ['k13', 'k3'])
        self.assertEqual(sorted(k1.match_prefix('k')), ['k13', 'k3'])
        self.assertEqual(sorted(k1.match_prefix('k', db=0)), ['k03', 'k3'])

        self.assertEqual(sorted(k0.match_regex('k')), ['k03', 'k3'])
        self.assertEqual(sorted(k0.match_regex('k', db=1)), ['k13', 'k3'])
        self.assertEqual(sorted(k1.match_regex('k')), ['k13', 'k3'])
        self.assertEqual(sorted(k1.match_regex('k', db=0)), ['k03', 'k3'])

        self.assertEqual(sorted(k0.keys()), ['i', 'j', 'k03', 'k3'])
        self.assertEqual(sorted(k0.keys(1)), ['i', 'j', 'k13', 'k3'])
        self.assertEqual(sorted(k1.keys()), ['i', 'j', 'k13', 'k3'])
        self.assertEqual(sorted(k1.keys(0)), ['i', 'j', 'k03', 'k3'])

        k0.clear()
        self.assertTrue('k3' not in k0)
        self.assertTrue('k3' in k1)
        k1.clear()
        self.assertTrue('k3' not in k1)


class TestMultipleThreads(BaseTestCase):
    server_kwargs = {'database': '*'}

    def test_multiple_threads(self):
        def write_and_read(n, s):
            for i in range(s, n + s):
                self.db.set('k%s' % i, 'v%s' % i)

            keys = ['k%s' % i for i in range(s, n + s)]
            result = self.db.get_bulk(keys)
            self.assertEqual(result, dict(('k%s' % i, 'v%s' % i)
                                          for i in range(s, n + s)))

        threads = [threading.Thread(target=write_and_read,
                                    args=(100, 100 * i)) for i in range(10)]
        for t in threads:
            t.daemon = True
            t.start()
        [t.join() for t in threads]


class TestConnectionPool(BaseTestCase):
    server_kwargs = {'database': '*'}

    def test_connection_pool(self):
        p = self.db.pool

        # Format is (in_use, free (binary), in_use, free (http)).
        self.assertEqual(p.stats, (0, 0, 0, 0))

        # Performing a DB operation will open a connection.
        self.assertEqual(self.db.set('k1', 'v1'), 1)
        self.assertEqual(self.db.get('k1'), 'v1')
        self.assertEqual(p.stats, (0, 1, 0, 0))

        # Performing an operation that uses the HTTP API opens an HTTP conn.
        self.assertTrue(self.db.exists('k1'))
        self.assertEqual(p.stats, (0, 1, 0, 1))

        # Using a separate thread is fine.
        def t_ops():
            self.assertEqual(self.db.set('k1', 'v1-x'), 1)
            self.assertEqual(self.db.get('k1'), 'v1-x')
            self.assertTrue('k1' in self.db)
        t = threading.Thread(target=t_ops)
        t.start()
        t.join()

        self.assertEqual(p.stats, (0, 1, 0, 1))

        self.db.close_all()
        self.assertEqual(p.stats, (0, 0, 0, 0))

    def test_many_threads(self):
        self.db.close_all()  # Ensure no open connections.
        p = self.db.pool
        def t_ops():
            for _ in range(10):
                self.db.get('kx')
        threads = [threading.Thread(target=t_ops) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = p.stats
        self.assertTrue(stats[0] == stats[2] == stats[3] == 0)
        self.assertTrue(stats[1] > 0)
        self.assertEqual(self.db.close_all(), stats[1])

    def test_max_age(self):
        self.db.close_all()

        p = self.db.pool
        s1 = p.create_socket()
        s2 = p.create_socket()

        now = time.time()
        p.free = [(now - 3601, s1), (now, s2)]
        s = p.checkout()
        self.assertTrue(s is s2)
        self.assertEqual(p.stats, (1, 0, 0, 0))
        self.assertTrue(s1.is_closed)
        p.checkin(s)
        self.assertEqual(p.stats, (0, 1, 0, 0))


class TestArrayMapSerialization(unittest.TestCase):
    def setUp(self):
        self.db = KyotoTycoon()

    def assertSerializeDict(self, dictobj):
        dictstr = self.db.serialize_dict(dictobj)
        self.assertEqual(self.db.deserialize_dict(dictstr), dictobj)

    def assertSerializeList(self, listobj):
        liststr = self.db.serialize_list(listobj)
        self.assertEqual(self.db.deserialize_list(liststr), listobj)

    def test_dict_serialize_deserialize(self):
        self.assertSerializeDict({'k1': 'v1', 'k2': 'v2'})
        self.assertSerializeDict({'k1': '', '': 'v2'})
        self.assertSerializeDict({'': ''})
        self.assertSerializeDict({'a' * 128: 'b' * 1024,
                                  'c' * 1024: 'd' * 1024 * 16,
                                  'e' * 1024 * 16: 'f' * 1024 * 1024,
                                  'g': 'g' * 128})
        self.assertSerializeDict({})

    def test_dict_serialization(self):
        serialize, deserialize = (self.db.serialize_dict,
                                  self.db.deserialize_dict)

        data = {'foo': 'baze'}
        dictstr = serialize(data)
        self.assertEqual(dictstr, b'\x03\x04foobaze')
        self.assertEqual(deserialize(dictstr), data)

        dictobj = deserialize(dictstr, decode_values=False)
        self.assertEqual(dictobj, {'foo': b'baze'})

        # Test edge cases.
        data = {'': ''}
        self.assertEqual(serialize(data), b'\x00\x00')

        self.assertEqual(serialize({}), b'')
        self.assertEqual(deserialize(b''), {})

    def test_list_serialize_deserialize(self):
        self.assertSerializeList(['foo', 'bar', 'nugget', 'baze'])
        self.assertSerializeList(['', 'zaizee', ''])
        self.assertSerializeList(['', '', ''])
        self.assertSerializeList(['a' * 128, 'b' * 1024 * 16,
                                  'c' * 1024 * 1024, 'd' * 1024])
        self.assertSerializeList([])

    def test_list_serialization(self):
        serialize, deserialize = (self.db.serialize_list,
                                  self.db.deserialize_list)
        # Simple tests.
        data = ['foo', 'baze', 'nugget', 'bar']
        liststr = serialize(data)
        self.assertEqual(liststr, b'\x03foo\x04baze\x06nugget\x03bar')
        self.assertEqual(deserialize(liststr), data)

        listobj = deserialize(liststr, decode_values=False)
        self.assertEqual(listobj, [b'foo', b'baze', b'nugget', b'bar'])

        # Test edge cases.
        data = ['', 'foo', '']
        self.assertEqual(serialize(data), b'\x00\x03foo\x00')

        self.assertEqual(serialize([]), b'')
        self.assertEqual(deserialize(b''), [])


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
