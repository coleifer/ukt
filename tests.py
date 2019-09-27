#!/usr/bin/env python

import datetime
import functools
import os
import pickle
import sys
import tempfile
import threading
import time
import unittest
import warnings

try:
    import msgpack
except ImportError:
    msgpack = None

from ukt import *
from ukt.client import EXPIRE


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

        kwargs = {'quiet': False}
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

    def get_client(self, serializer):
        return KyotoTycoon(self._server.host, self._server.port,
                           serializer=serializer)


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

    def test_http_crud(self):
        self.assertTrue(self.db.set_http('k1', 'v1'))
        resp = self.db.set_bulk_http({'k1': 'v1-x', 'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(resp, 3)

        self.assertEqual(self.db.get_http('k1'), 'v1-x')
        self.assertEqual(self.db.remove_http('k2'), 1)
        self.assertEqual(self.db.remove_http('k2'), 0)

        self.assertEqual(self.db.get_bulk_http(['k1', 'k2', 'k3']),
                         {'k1': 'v1-x', 'k3': 'v3'})
        self.assertEqual(self.db.remove_bulk_http(['k1', 'k2', 'k3']), 2)

    def test_http_signal(self):
        def wait_get():
            val = self.db.get_http('k1', signal='sig1', wait=2)
            self.assertEqual(val, 'v1-x')
        t = threading.Thread(target=wait_get)
        t.start()

        r = self.db.set_bulk_http({'k1': 'v1-x', 'k2': 'v2-y'}, signal='sig1',
                                  send=True)
        t.join()
        self.assertEqual(r, 2)

        def wait_seize():
            val = self.db.seize('k1', signal='sig2', wait=2)
            self.assertEqual(val, 'v1-z')
        t = threading.Thread(target=wait_seize)
        t.start()

        # Send an arbitrary signal.
        r = self.db.set_http('k1', 'v1-y', signal='sigx', send=True)
        self.assertEqual(r, 1)

        # Send the actual signal we are waiting for in our thread.
        r = self.db.set_http('k1', 'v1-z', signal='sig2', send=True)
        self.assertEqual(r, 1)
        t.join()

        if self.db.count() != 1:
            warnings.warn('HTTP signals test is being flaky.')
        else:
            self.assertEqual(self.db.count(), 1)
            self.assertEqual(self.db.keys_nonlazy(), ['k2'])

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

    def test_decoding_errors_handling(self):
        keys = [b'foo\xfe\xff', b'bar\x00\xffnug']
        for key in keys:
            self.db.set(key, 'testing')

        for key in keys:
            self.assertEqual(self.db.get(key), 'testing')

        self.assertEqual(self.db.get_bulk(keys),
                         dict(zip(keys, ('testing', 'testing'))))
        dbkeys = [(0, key) for key in keys]
        self.assertEqual([i[1:-1] for i in self.db.get_bulk_details(dbkeys)],
                         [(keys[0], 'testing'), (keys[1], 'testing')])

        self.db.set_bulk({'k1': 'v1', 'k2': 'v2'})

        # What happens if we try to unpickle data that is not pickled?
        db = self.get_client(KT_PICKLE)
        db.set('k3', 'v3')
        self.assertRaises(Exception, db.get_bulk, ['k1', 'k2'])
        self.assertRaises(Exception, db.get_bulk_details, ['k1', 'k2'])
        self.assertRaises(Exception, db.get, 'k1')

        # Connection is still OK.
        self.assertEqual(db.get('k3'), 'v3')


class TestHash(KyotoTycoonTests, BaseTestCase):
    server_kwargs = {'database': '*'}


class TestBTree(KyotoTycoonTests, BaseTestCase):
    server_kwargs = {'database': '%'}


class TestCursor(BaseTestCase):
    server_kwargs = {'database': '%'}

    def setUp(self):
        super(TestCursor, self).setUp()
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
        self.assertEqual(list(cursor), [])
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

    def test_cursor_iteration(self):
        c = self.db.cursor()
        c.jump('k2')
        self.assertEqual(list(c), [('k2', 'v2'), ('k3', 'v3'), ('k4', 'v4')])

        # Mark for backwards iteration.
        self.assertTrue(c.jump_back('k2x'))
        self.assertEqual(list(c), [('k2', 'v2'), ('k1', 'v1')])

        # Mark for forwards iteration.
        self.assertTrue(c.jump('k2x'))
        self.assertEqual(list(c), [('k3', 'v3'), ('k4', 'v4')])

        # Jumping to invalid records will cause us to iterate the full set.
        self.assertFalse(c.jump('kx'))
        self.assertEqual(list(c), [])
        self.assertFalse(c.jump_back('k0'))
        self.assertEqual(list(c), [])

        # However we can jump back and iterate again.
        self.assertTrue(c.jump('k3'))
        self.assertEqual(list(c), [('k3', 'v3'), ('k4', 'v4')])

    def test_read_write_step(self):
        c = self.db.cursor()
        self.assertTrue(c.jump('k0x'))  # Positioned at k1.
        self.assertEqual(c.value(True), 'v1')
        self.assertTrue(c.set_value('v2-x', True))
        self.assertEqual(c.get(step=True), ('k3', 'v3'))
        self.assertEqual(c.seize(), ('k4', 'v4'))
        self.assertTrue(c.is_valid())
        self.assertTrue(c.key(True) is None)
        self.assertFalse(c.set_value('xx'))
        self.assertFalse(c.remove())

        c.jump_back()
        self.assertEqual(list(c), [('k3', 'v3'), ('k2', 'v2-x'), ('k1', 'v1')])
        self.assertTrue(c.get(step=True) is None)

    def test_seize_remove_step(self):
        # Unclear about the STEP parameter for seize operation.
        c = self.db.cursor()
        c.jump()
        self.assertEqual(c.seize(), ('k1', 'v1'))
        self.assertEqual(c.seize(), ('k2', 'v2'))
        self.assertEqual(c.get(True), ('k3', 'v3'))
        self.assertTrue(c.remove())  # Remove k4.

        self.db.set('k1', 'v1-a')
        self.db.set('k2', 'v2-b')
        c.jump()
        self.assertTrue(c.remove())
        self.assertEqual(list(c), [('k2', 'v2-b'), ('k3', 'v3')])


class TestSerializers(BaseTestCase):
    server_kwargs = {'database': '*'}

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

        self.assertEqual(db.set_bulk({'k3': None, 'k4': 0}), 2)

        self.assertEqual(db.get_bulk(['k1', 'k2', 'k3', 'k4']), {
            'k1': obj,
            'k2': '',
            'k3': None,
            'k4': 0})

        # Use HTTP APIs as well.
        l = ['foo', 'bar']
        db.replace('k3', l)
        self.assertEqual(db.get('k3'), l)
        self.assertTrue(db.cas('k3', l, ['new', 'list']))
        self.assertEqual(db.get('k3'), ['new', 'list'])

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


class TestMultiDB(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {'database': '%', 'server_args': ['-scr', lua_script, '*']}

    def tearDown(self):
        super(TestMultiDB, self).tearDown()
        self.db.clear(0)
        self.db.clear(1)

    def test_multiple_databases_present(self):
        report = self.db.report()
        self.assertTrue('db_0' in report)
        self.assertTrue('db_1' in report)
        self.assertTrue(report['db_0'].endswith(b'path=*'))
        self.assertTrue(report['db_1'].endswith(b'path=%'))

    def test_list_databases(self):
        self.assertEqual(self.db.databases, ['*', '%'])

        db_status = self.db.list_databases()
        (hpath, hstatus), (tpath, tstatus) = db_status
        self.assertEqual(hpath, '*')
        self.assertEqual(hstatus['count'], 0)
        self.assertEqual(tpath, '%')
        self.assertEqual(tstatus['count'], 0)

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

    def test_details_apis(self):
        xt = int(time.time()) + 3600
        xt_none = 0xffffffffff
        n = self.db.set_bulk_details([
            (0, 'k1', 'v1-0', None),
            (1, 'k1', 'v1-1', -xt),
            (1, 'k2', 'v2', -xt),
            (0, 'k3', 'v3', None)])
        self.assertEqual(n, 4)

        res = self.db.get_bulk_details([
            (0, 'k1'), (1, 'k1'), (0, 'k2'), (1, 'k2'),
            (0, 'kx'), (1, 'ky'), (2, 'xx')])
        self.assertEqual(res, [
            (0, 'k1', 'v1-0', xt_none),
            (1, 'k1', 'v1-1', xt),
            (1, 'k2', 'v2', xt)])

        n = self.db.remove_bulk_details([
            (0, 'k1'),
            (0, 'k2'),
            (1, 'k1'),
            (1, 'k3')])
        self.assertEqual(n, 2)

        res = self.db.get_bulk_details([
            (0, 'k1'), (0, 'k2'), (0, 'k3'),
            (1, 'k1'), (1, 'k2'), (1, 'k3')])
        self.assertEqual(res, [(0, 'k3', 'v3', xt_none), (1, 'k2', 'v2', xt)])


class BaseLuaTestCase(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {
        'database': '%',
        'server_args': ['-scr', lua_script]}


class TestLuaExpireTime(BaseLuaTestCase):
    def assertXT(self, keys, expected):
        res = self.db.get_bulk_details([(0, k) for k in keys])
        xts = {k: (v, xt) for _, k, v, xt in res}
        self.assertEqual(xts, expected)

    def test_expire_time_handling(self):
        dt = datetime.datetime.now().replace(microsecond=0)
        dt += datetime.timedelta(seconds=3600)
        dt_ts = time.mktime(dt.timetuple())
        xt = int(time.time()) + 600
        xt_none = 0xffffffffff

        # Set the expire time in a variety of ways.
        self.db.set('k1', 'v1', expire_time=dt)
        self.db.set_bulk_details([
            (0, 'k2', 'v2', dt),
            (0, 'k3', 'v3', xt),
            (0, 'k4', 'v4', None)])
        self.db.add('k5', 'v5', expire_time=dt)

        self.assertXT(['k1', 'k2', 'k3', 'k4', 'k5'], {
            'k1': ('v1', dt_ts),
            'k2': ('v2', dt_ts),
            'k3': ('v3', xt),
            'k4': ('v4', xt_none),
            'k5': ('v5', dt_ts)})

        # Ensure relative times work as expected.
        ts = int(time.time()) + 300
        self.db.replace('k1', 'v1-x', expire_time=ts)
        ttl = self.db.expire_time('k1')
        self.assertTrue(abs(ttl - ts) < 2)

        # We can also provide a timedelta.
        td = datetime.timedelta(seconds=600)
        ts = int(time.time()) + 600
        self.db.replace('k1', 'v1-y', expire_time=td)
        ttl = self.db.expire_time('k1')
        self.assertTrue(abs(ttl - ts) < 2)

    def test_expires(self):
        dt = datetime.datetime.now().replace(microsecond=0)
        dt += datetime.timedelta(seconds=3600)
        self.db.set('k1', 'v1', expire_time=dt)
        self.assertEqual(self.db.expires('k1'), dt)
        self.db.set('k2', 'v2')
        self.assertEqual(self.db.expires('k2'), datetime.datetime.max)
        self.assertTrue(self.db.expires('k3') is None)

    def test_script_touch(self):
        now = int(time.time())

        # Negative expire times are treated as epoch time.
        xt1 = now + 100
        xt2 = now + 200
        xt_none = 0xffffffffff
        self.db.set('k1', 'v1', expire_time=xt1)
        self.db.set('k2', 'v2', expire_time=xt2)
        self.db.set('k3', 'v3')

        self.assertXT(['k1', 'k2', 'k3'], {
            'k1': ('v1', xt1),
            'k2': ('v2', xt2),
            'k3': ('v3', xt_none)})

        # Update the timestamp and verify the return value.
        xt1_1 = now + 300
        res = self.db.touch('k1', xt1_1)
        self.assertEqual(res, xt1)
        self.assertXT(['k1'], {'k1': ('v1', xt1_1)})

        # We can also pass a relative value.
        res = self.db.touch('k1', 300)
        self.assertEqual(res, xt1_1)
        self.assertXT(['k1'], {'k1': ('v1', xt1_1)})

        # Test that leaving the timestamp unchanged also works as expected.
        res = self.db.touch('k2', xt2)
        self.assertEqual(res, xt2)
        self.assertXT(['k1', 'k2', 'k3'], {
            'k1': ('v1', xt1_1),
            'k2': ('v2', xt2),
            'k3': ('v3', xt_none)})

        # Test relative timestamps.
        xt1_2 = int(time.time()) + 60
        self.db.touch('k1', 60)

        # Leave the relative timestamp unchanged.
        old_xt = self.db.touch('k1', 60)
        self.assertTrue(abs(old_xt - xt1_2) < 2)

        # And again, using the absolute timestamp.
        self.db.touch('k1', xt1_2)

        # Test using non-existent key.
        old_xt = self.db.touch('kx')
        self.assertTrue(old_xt is None)

        # Test clearing the timestamp.
        self.db.touch('k1')
        self.assertXT(['k1'], {'k1': ('v1', xt_none)})

        # Verify that clearing it again results in no change.
        old_xt = self.db.touch('k1')
        self.assertEqual(old_xt, xt_none)

        # And check that we can set a cleared key.
        old_xt = self.db.touch('k3', xt1)
        self.assertEqual(old_xt, xt_none)

        # Verify final state.
        self.assertXT(['k1', 'k2', 'k3'], {
            'k1': ('v1', xt_none),
            'k2': ('v2', xt2),
            'k3': ('v3', xt1)})

    def test_script_touch_bulk(self):
        now = int(time.time())

        # Negative expire times are treated as epoch time.
        xt1 = now + 100
        xt2 = now + 200
        xt_none = 0xffffffffff
        self.db.set_bulk_details([
            (0, 'k1', 'v1', xt1),
            (0, 'k2', 'v2', xt2),
            (0, 'k3', 'v3', 60),
            (0, 'k4', 'v4', None)])

        xt1_1 = now + 300
        res = self.db.touch_bulk(['k1', 'k3', 'kx'], xt1_1)
        self.assertEqual(res, {'k1': xt1, 'k3': now + 60})

        self.assertXT(['k1', 'k2', 'k3', 'k4'], {
            'k1': ('v1', xt1_1),
            'k2': ('v2', xt2),
            'k3': ('v3', xt1_1),
            'k4': ('v4', xt_none)})

        res = self.db.touch_bulk(['k2', 'k4'])
        self.assertEqual(res, {'k2': xt2, 'k4': xt_none})

        self.assertXT(['k1', 'k2', 'k3', 'k4'], {
            'k1': ('v1', xt1_1),
            'k2': ('v2', xt_none),
            'k3': ('v3', xt1_1),
            'k4': ('v4', xt_none)})

        self.assertEqual(self.db.touch_bulk([]), {})

    def test_script_touch_relative(self):
        now = int(time.time())

        # Negative expire times are treated as epoch time.
        xt1 = now + 100
        xt2 = now + 200
        xt_none = 0xffffffffff
        self.db.set_bulk_details([
            (0, 'k1', 'v1', xt1),
            (0, 'k2', 'v2', xt2),
            (0, 'k3', 'v3', 60),
            (0, 'k4', 'v4', None)])

        # First verify that the TTL for k3 is roughly 60s from now.
        xt3 = now + 60
        ttl = self.db.expire_time('k3')
        self.assertTrue(abs(xt3 - ttl) < 2)

        out = self.db.touch_bulk_relative(['k1', 'k3'], 300)
        self.assertEqual(out, {
            'k1': xt1 + 300,
            'k3': ttl + 300})

        self.assertXT(['k1', 'k2', 'k3', 'k4'], {
            'k1': ('v1', xt1 + 300),
            'k2': ('v2', xt2),
            'k3': ('v3', ttl + 300),
            'k4': ('v4', xt_none)})

        # Reports the XT of k4 to be 0xffffffffff + 10, but really the max
        # value is kt_none, so it retains that value when re-reading.
        out = self.db.touch_bulk_relative(['k2', 'k4', 'kx'], 10)
        self.assertEqual(out, {
            'k2': xt2 + 10,
            'k4': xt_none + 10})

        self.assertXT(['k1', 'k2', 'k3', 'k4'], {
            'k1': ('v1', xt1 + 300),
            'k2': ('v2', xt2 + 10),
            'k3': ('v3', ttl + 300),
            'k4': ('v4', xt_none)})

        self.assertEqual(self.db.expire_time('k1'), xt1 + 300)
        self.assertEqual(self.db.expire_time('k2'), xt2 + 10)
        self.assertEqual(self.db.expire_time('k4'), xt_none)
        self.assertEqual(self.db.expire_time('kx'), None)

        # Verify we can use touch_relative() and also set negative intervals.
        out = self.db.touch_relative('k1', -100)
        self.assertEqual(out, xt1 + 200)
        self.assertEqual(self.db.expire_time('k1'), xt1 + 200)


class TestLuaErrorCode(BaseLuaTestCase):
    def test_error_codes(self):
        def trigger(flag):
            return self.db.script('_error_code', {'flag': str(flag)})

        self.assertEqual(trigger(0), {})
        expected = (
            (1, 'noimpl'),
            (2, 'invalid'),
            (3, 'logic'),
            (4, 'internal'),
            (5, 'norepos'),
            (6, 'noperm'),
            (7, 'broken'),
            (8, 'duprec'),
            (9, 'norec'),
            (10, 'system'),
            (11, 'misc'))
        for flag, msg in expected:
            with self.assertRaises(ProtocolError):
                trigger(flag)
                code, resp_msg = self.db.error()
                self.assertEqual(msg, resp_msg)

        # After a successful operation, we get the success code.
        self.db.set('kx', 'vx')
        code, resp_msg = self.db.error()
        self.assertEqual(resp_msg, 'success')

        # Even though this fails, the error is not set to duprec? Just
        # documenting this weird behavior.
        self.assertFalse(self.db.add('kx', 'vx2'))
        code, resp_msg = self.db.error()
        self.assertEqual(resp_msg, 'success')


class TestLua(BaseLuaTestCase):
    def test_script_set(self):
        L = self.db.lua

        # Test adding a single item.
        self.assertEqual(L.sadd(key='s1', x='foo'), {'num': '1'})
        self.assertEqual(L.sadd(key='s1', x='foo'), {'num': '0'})

        # Test adding multiple items.
        items = ['bar', 'baz', 'nug']
        ret = L.sadd(key='s1', **{str(i): k for i, k in enumerate(items)})
        self.assertEqual(ret, {'num': '3'})

        # Test get cardinality.
        self.assertEqual(L.scard(key='s1'), {'num': '4'})

        # Test membership.
        self.assertEqual(L.sismember(key='s1', value='bar'), {'num': '1'})
        self.assertEqual(L.sismember(key='s1', value='baze'), {'num': '0'})

        keys = ['bar', 'baz', 'foo', 'nug']

        # Test get members.
        self.assertEqual(sorted(L.smembers(key='s1').values()), sorted(keys))
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
        L.sadd(key='s1', **{str(i): k for i, k in enumerate(keys)})
        self.assertEqual(L.srem(key='s1', x='nug'), {'num': '1'})
        self.assertEqual(L.srem(key='s1', x='nug'), {'num': '0'})

        # Create another set, s2 {baze, foo, zai}.
        L.sadd(key='s2', a='baze', b='foo', c='zai')

        # Test multiple set operations, {bar, baz, foo} | {baze, foo, zai}.
        res = L.sinter(key='s1', key2='s2').values()
        self.assertEqual(sorted(res), ['foo'])
        res = L.sunion(key='s1', key2='s2').values()
        self.assertEqual(sorted(res), ['bar', 'baz', 'baze', 'foo', 'zai'])

        res = L.sdiff(key='s1', key2='s2').values()
        self.assertEqual(sorted(res), ['bar', 'baz'])
        res = L.sdiff(key='s2', key2='s1').values()
        self.assertEqual(sorted(res), ['baze', 'zai'])

        res = L.sdiff(key='s1', key2='s2', dest='s3').values()
        self.assertEqual(sorted(res), ['bar', 'baz'])
        res = L.smembers(key='s3').values()
        self.assertEqual(sorted(res), ['bar', 'baz'])

    def test_script_list(self):
        L = self.db.lua

        self.assertEqual(L.lrpush(key='l1', value='i0'), {'length': '1'})
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
        self.assertEqual(L.lset(key='l1', index=2, value='i2-x'), {'num': '1'})
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
        self.assertEqual(R(start=1, stop=4), {'0': 'i1', '1': 'i2', '2': 'i3'})
        self.assertEqual(R(start=0, stop=1), {'0': 'i0'})
        self.assertEqual(R(start=3), {'0': 'i3', '1': 'i4'})
        self.assertEqual(R(stop=-3), {'0': 'i0', '1': 'i1'})
        self.assertEqual(R(start=1, stop=-3), {'0': 'i1'})
        self.assertEqual(R(start=3, stop=-1), {'0': 'i3'})
        self.assertEqual(R(start=-1), {'0': 'i4'})
        self.assertEqual(R(start=-2), {'0': 'i3', '1': 'i4'})

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


class TestLuaMultiDB(BaseTestCase):
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
            kwargs = {str(i): 'v%s' % i, 'db': i % 2}
            L.sadd(key='s1', **kwargs)

        self.assertEqual(L.scard(key='s1', db=0), {'num': '3'})
        self.assertEqual(L.scard(key='s1', db=1), {'num': '2'})

        # By default the database is 0.
        self.assertEqual(sorted(L.smembers(key='s1').values()),
                         ['v0', 'v2', 'v4'])
        self.assertEqual(sorted(L.smembers(key='s1', db=0).values()),
                         ['v0', 'v2', 'v4'])
        self.assertEqual(sorted(L.smembers(key='s1', db=1).values()),
                         ['v1', 'v3'])

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


class TestLuaContainers(BaseLuaTestCase):
    server_kwargs = {
        'serializer': KT_PICKLE,
        'database': '%',
        'server_args': ['-scr', BaseLuaTestCase.lua_script]}

    def test_hash(self):
        data = {
            'k1': 'v1',
            'k2': ['i0', 'i1', 'i2'],
            'k3': {'x1': 'y1', 'x2': 'y2'}}

        h = self.db.Hash('h1')
        self.assertEqual(h.set_bulk(data), 3)
        self.assertEqual(h.set_bulk({}), 0)
        self.assertEqual(h.get_bulk(['k1', 'k2', 'k3', 'kx']), data)
        self.assertEqual(h.get_bulk(['x1', 'x2']), {})
        self.assertEqual(h.get_bulk([]), {})

        self.assertEqual(h['k2'], ['i0', 'i1', 'i2'])
        self.assertTrue(h['kx'] is None)

        h['k4'] = ['foo', 'baz']
        self.assertEqual(h.setnx('k1', 'v1-x'), 0)
        self.assertEqual(h.set('k1', 'v1-y'), 1)
        self.assertEqual(len(h), 4)

        self.assertEqual(h.remove_bulk(['k1', 'k3', 'kx']), 2)
        self.assertEqual(h.remove_bulk(['k1', 'k3', 'kx']), 0)
        self.assertEqual(h.remove_bulk([]), 0)
        self.assertEqual(len(h), 2)
        self.assertEqual(h.get_all(),
                         {'k2': ['i0', 'i1', 'i2'], 'k4': ['foo', 'baz']})

        self.assertEqual(h.remove('k2'), 1)
        self.assertEqual(h.remove('k2'), 0)
        self.assertEqual(h.get_all(), {'k4': ['foo', 'baz']})

        self.assertTrue('k4' in h)
        self.assertFalse('k2' in h)

        h.set('k1', 'v1-z')
        h.set('k3', 'v3-z')
        del h['k4']
        self.assertEqual(h['k1'], 'v1-z')
        self.assertEqual(h.get_all(), {'k1': 'v1-z', 'k3': 'v3-z'})

        # Ensure we can fetch the raw data from KT and deserialize it using the
        # python implementation of mapload.
        self.assertEqual(h.get_raw(), {'k1': 'v1-z', 'k3': 'v3-z'})

        # Ensure that the data is stored in the right key.
        self.assertTrue(self.db.get_bytes('h1') is not None)
        self.assertEqual(self.db.count(), 1)

    def test_hash_pack(self):
        h = self.db.Hash('h1')
        data = {'k%02d' % i: 'v%s' % i for i in range(10)}
        self.db.set_bulk(data)
        self.assertEqual(h.pack(), 10)
        self.assertEqual(h.get_all(), data)
        h.clear()

        h = self.db.Hash('a1')
        def reset():
            h.clear()
            h.set_bulk({'k01': 'v1-x', 'kx': 'vx'})
        reset()

        self.assertEqual(h.pack('k01', 'k03'), 2)
        self.assertEqual(h.get_all(), {'k01': 'v1', 'k02': 'v2', 'kx': 'vx'})
        reset()

        # Look at behavior of partial keys.
        self.assertEqual(h.pack('k03x', 'k05x'), 2)
        self.assertEqual(h.get_all(), {'k01': 'v1-x', 'k04': 'v4',
                                       'k05': 'v5', 'kx': 'vx'})
        reset()

        self.assertEqual(h.pack('k08'), 2)
        self.assertEqual(h.get_all(), {'k01': 'v1-x', 'k08': 'v8',
                                       'k09': 'v9', 'kx': 'vx'})
        reset()

        # Move hash to end of database.
        old_key = h.key
        hdata = self.db.get_bytes(old_key)
        h.key = 'z1'
        self.db.set(h.key, hdata, encode_value=False)
        self.db.remove(old_key)

        self.assertEqual(h.pack(stop='k02'), 2)
        self.assertEqual(h.get_all(), {'k01': 'v1', 'k00': 'v0', 'kx': 'vx'})
        reset()

        self.assertEqual(h.pack(start='zz'), 0)
        self.assertEqual(h.pack(start='zz', stop='zzz'), 0)
        self.assertEqual(h.pack(start='a', stop='aa'), 0)
        self.assertEqual(h.pack(stop='aa'), 0)
        self.assertEqual(h.pack('k2', 'k4', 0), 0)
        self.assertEqual(h.get_all(), {'k01': 'v1-x', 'kx': 'vx'})

    def test_set(self):
        s = self.db.Set('s1')
        self.assertEqual(s.add('k1'), 1)
        self.assertEqual(s.add('k1'), 0)
        self.assertEqual(s.add_bulk(['k2', 'k3', 'k4', 'k1']), 3)
        self.assertEqual(s.add_bulk(['k2', 'k3', 'k4', 'k1']), 0)
        self.assertEqual(s.add_bulk([]), 0)
        self.assertEqual(len(s), 4)
        self.assertTrue('k1' in s)
        self.assertFalse('kx' in s)

        data = set(('k1', 'k2', 'k3', 'k4'))
        self.assertEqual(s.members(), data)
        self.assertTrue(s.pop() in data)
        self.assertTrue(s.pop() in data)
        self.assertEqual(s.count(), 2)

        self.assertEqual(s.add_bulk(data), 2)
        self.assertEqual(s.members(), data)

        self.assertEqual(s.remove('k2'), 1)
        self.assertEqual(s.remove('k2'), 0)

        self.assertEqual(s.remove_bulk(('k1', 'k3', 'kx')), 2)
        self.assertEqual(s.remove_bulk(('k1', 'k3', 'kx')), 0)
        self.assertEqual(s.remove_bulk([]), 0)
        self.assertEqual(s.members(), set(('k4',)))

        self.assertTrue(self.db.exists('s1'))
        self.assertEqual(self.db.count(), 1)

        # Verify that serialization works correctly.
        s2 = self.db.Set('s2')
        items = [100, 13.37, False, None, ('foo', 'bar')]
        s2.add(*items)
        self.assertEqual(s2.members(), set(items))
        for item in items:
            self.assertTrue(item in s2)
        self.assertTrue(s2.pop() in items)
        self.assertTrue(s2.pop() in items)
        self.assertEqual(len(s2), 3)

        # Verify popping from an empty set.
        s3 = self.db.Set('s3')
        self.assertTrue(s3.pop() is None)
        self.assertEqual(s3.remove('xx'), 0)
        self.assertEqual(s3.members(), set())

    def test_set_operations(self):
        s1 = self.db.Set('s1')
        s2 = self.db.Set('s2')
        sx = self.db.Set('sx')
        s1.add('k1', 'k2', 'k3')
        s2.add('k3', 'k4', 'k5')

        self.assertEqual(s1.intersection(s2), set(('k3',)))
        self.assertEqual(s1.union(s2), set(('k1', 'k2', 'k3', 'k4', 'k5')))
        self.assertEqual(s1.difference(s2), set(('k1', 'k2')))

        self.assertEqual(s2.intersection(s1), set(('k3',)))
        self.assertEqual(s2.union(s1), set(('k1', 'k2', 'k3', 'k4', 'k5')))
        self.assertEqual(s2.difference(s1), set(('k4', 'k5')))

        # Compare against empty/missing set.
        self.assertEqual(s1.intersection(sx), set())
        self.assertEqual(s1.union(sx), set(('k1', 'k2', 'k3')))
        self.assertEqual(s1.difference(sx), set(('k1', 'k2', 'k3')))
        self.assertEqual(sx.intersection(s1), set())
        self.assertEqual(sx.union(s1), set(('k1', 'k2', 'k3')))
        self.assertEqual(sx.difference(s1), set())

        # Store results.
        self.assertEqual(s1.intersection(s2, dest=sx), set(('k3',)))
        self.assertEqual(sx.members(), set(('k3',)))
        sx.clear()

        self.assertEqual(s1.union(s2, dest=sx),
                         set(('k1', 'k2', 'k3', 'k4', 'k5')))
        self.assertEqual(sx.members(), set(('k1', 'k2', 'k3', 'k4', 'k5')))
        sx.clear()

        self.assertEqual(s1.difference(s2, dest=sx), set(('k1', 'k2')))
        self.assertEqual(sx.members(), set(('k1', 'k2')))
        sx.clear()

    def test_list(self):
        l = self.db.List('l1')
        self.assertEqual(l.append('i2'), 1)
        self.assertEqual(l.appendleft('i1'), 2)
        self.assertEqual(l.appendright('i4'), 3)
        self.assertEqual(l.insert(2, 'i3'), 4)
        self.assertEqual(l.get_range(), ['i1', 'i2', 'i3', 'i4'])
        self.assertEqual(l[0], 'i1')
        self.assertEqual(l[1], 'i2')
        self.assertEqual(l[-1], 'i4')
        self.assertEqual(l[-2], 'i3')

        l[2] = 'i3-x'
        self.assertEqual(l[:], ['i1', 'i2', 'i3-x', 'i4'])
        self.assertEqual(l.popleft(), 'i1')
        self.assertEqual(l.popright(), 'i4')

        l.append('i5-y')
        l.insert(-1, 'i4-y')
        self.assertEqual(l[:], ['i2', 'i3-x', 'i4-y', 'i5-y'])
        l.set(3, 'i5-z')
        self.assertEqual(l.pop(2), 'i4-y')
        self.assertEqual(l.pop(2), 'i5-z')
        self.assertEqual(len(l), 2)
        self.assertEqual(l[:], ['i2', 'i3-x'])

        l.insert(0, 'i1')
        l.append('i4')
        self.assertEqual(len(l), 4)
        self.assertEqual(l[1:-1], ['i2', 'i3-x'])

        # Ensure we can fetch the raw data from KT and deserialize it using the
        # python implementation of mapload.
        self.assertEqual(l.get_raw(), ['i1', 'i2', 'i3-x', 'i4'])

        self.assertTrue(self.db.exists('l1'))
        self.assertEqual(self.db.count(), 1)

    def test_list_find(self):
        l = self.db.List('l1')
        l.extend(['i1', 'i2', 'i3', 'i2', 'i1'])
        self.assertEqual(l.find('i1'), 0)
        self.assertEqual(l.rfind('i1'), 4)
        self.assertEqual(l.find('i2'), 1)
        self.assertEqual(l.rfind('i2'), 3)
        self.assertEqual(l.find('i3'), 2)
        self.assertEqual(l.rfind('i3'), 2)

        self.assertTrue(l.find('ix') is None)
        self.assertTrue(l.rfind('ix') is None)

    def test_list_ranges(self):
        l = self.db.List('l1')
        # Set list to i0...i9.
        self.assertEqual(l.extend(['i2']), 1)
        self.assertEqual(l.extend([]), 1)
        self.assertEqual(l.extend(['i3', 'i4', 'i5', 'i6', 'i7']), 6)
        self.assertEqual(l.insert(0, 'i1'), 7)
        self.assertEqual(l.appendleft('i0'), 8)
        self.assertEqual(l.extend(['i8', 'i9']), 10)
        self.assertEqual(l.get_range(), ['i%s' % i for i in range(10)])

        self.assertEqual(l.get_range(8), ['i8', 'i9'])
        self.assertEqual(l.get_range(2, 4), ['i2', 'i3'])
        self.assertEqual(l.get_range(3, -3), ['i3', 'i4', 'i5', 'i6'])
        self.assertEqual(l.get_range(-3, -1), ['i7', 'i8'])

        self.assertEqual(l.remove_range(8), 8)
        self.assertEqual(l.remove_range(3, 6), 5)
        self.assertEqual(l.get_range(), ['i0', 'i1', 'i2', 'i6', 'i7'])

        self.assertEqual(l.remove_range(-3, -1), 3)
        self.assertEqual(l.get_range(), ['i0', 'i1', 'i7'])

        self.assertEqual(l.remove_range(-3, 1), 2)
        self.assertEqual(l.get_range(), ['i1', 'i7'])
        self.assertEqual(l.get_range(0, 5), ['i1', 'i7'])
        self.assertEqual(l.get_range(2, 5), [])

        self.assertEqual(l.remove_range(), 0)
        self.assertEqual(l.get_range(), [])

        # List is empty, we can still call remove_range() and request ranges.
        self.assertEqual(l.remove_range(), 0)
        self.assertEqual(l.get_range(), [])
        self.assertEqual(l.get_range(3), [])
        self.assertEqual(l.get_range(-2, -4), [])

    def test_empty_list(self):
        l = self.db.List('l1')
        self.assertTrue(l.popleft() is None)
        self.assertTrue(l.popright() is None)
        self.assertTrue(l.pop(0) is None)
        self.assertRaises(IndexError, l.remove, 0)
        self.assertEqual(l[3:], [])
        self.assertEqual(l[:3], [])
        self.assertRaises(IndexError, lambda: l[3])
        self.assertRaises(IndexError, lambda: l[-1])
        self.assertRaises(IndexError, lambda: l.set(2, 'foo'))
        self.assertRaises(IndexError, lambda: l.set(0, 'foo'))

        # Cannot insert into an empty list at a non-zero location.
        self.assertRaises(IndexError, lambda: l.insert(1, 'foo'))
        self.assertEqual(l.insert(0, 'bar'), 1)
        self.assertEqual(l[:], ['bar'])
        l.clear()
        self.assertEqual(l.insert(-1, 'baz'), 1)
        self.assertEqual(l[:], ['baz'])
        self.assertRaises(IndexError, lambda: l.insert(2, 'foo'))
        self.assertEqual(l.insert(-1, 'nug'), 2)
        self.assertEqual(l[:], ['nug', 'baz'])

    def test_list_poppush(self):
        l1 = self.db.List('l1')
        l2 = self.db.List('l2')

        def assertLists(l1_val, l2_val):
            self.assertEqual(list(l1), l1_val)
            self.assertEqual(list(l2), l2_val)

        l1.extend(['i0', 'i1', 'i2', 'i3'])
        self.assertEqual(l1.lpoprpush(l2), 'i0')
        assertLists(['i1', 'i2', 'i3'], ['i0'])

        self.assertEqual(l1.rpoplpush(l2), 'i3')
        assertLists(['i1', 'i2'], ['i3', 'i0'])

        self.assertEqual(l1.lpoprpush('l2'), 'i1')
        self.assertEqual(l1.rpoplpush('l2'), 'i2')
        self.assertRaises(IndexError, l1.lpoprpush, l2)
        self.assertRaises(IndexError, l1.rpoplpush, l2)
        assertLists([], ['i2', 'i3', 'i0', 'i1'])

        # Test rotate.
        self.assertEqual(l2.lpoprpush(), 'i2')
        assertLists([], ['i3', 'i0', 'i1', 'i2'])
        self.assertEqual(l2.rpoplpush(), 'i2')
        assertLists([], ['i2', 'i3', 'i0', 'i1'])

        # Can't rotate an empty list.
        self.assertRaises(IndexError, l1.lpoprpush, l1)
        self.assertRaises(IndexError, l1.rpoplpush, l1)

    def test_list_unpack(self):
        l = self.db.List('l1')
        l.extend(['i%s' % i for i in range(10)])

        # Simple case.
        self.assertEqual(l.unpack(), 10)
        self.assertEqual(self.db.count(), 11)

        expected = {
            'l1:%04d' % i: 'i%s' % i
            for i in range(10)}
        self.assertEqual(self.db.get_bulk(list(expected)), expected)

        # With parameters. Will store i3..i6 in p1:00 -> p1:03.
        self.assertEqual(l.unpack(3, -3, 'p1:', '%02d'), 4)
        expected = {'p1:%02d' % i: 'i%s' % (i + 3) for i in range(4)}
        self.assertEqual(self.db.get_bulk(list(expected)), expected)
        self.assertEqual(self.db['p1:00'], 'i3')
        self.assertEqual(self.db['p1:03'], 'i6')

    def test_list_pack(self):
        l = self.db.List('l1')
        self.db.set_bulk({'k%02d' % i: 'i%s' % i for i in range(10)})
        self.assertEqual(l.pack(), 10)
        self.assertEqual(l.get_range(), ['i%s' % i for i in range(10)])
        l.clear()

        l = self.db.List('a1')
        l.extend(['foo', 'bar'])
        def reset():
            self.assertEqual(l.remove_range(2), 2)
            self.assertEqual(l.get_range(), ['foo', 'bar'])

        self.assertEqual(l.pack('k01', 'k04'), 3)
        self.assertEqual(l.get_range(), ['foo', 'bar', 'i1', 'i2', 'i3'])
        reset()

        # Look at behavior of partial keys.
        self.assertEqual(l.pack('k03x', 'k05x'), 2)
        self.assertEqual(l.get_range(), ['foo', 'bar', 'i4', 'i5'])
        reset()

        self.assertEqual(l.pack('k08'), 2)
        self.assertEqual(l.get_range(), ['foo', 'bar', 'i8', 'i9'])
        reset()

        # Move list to end of database.
        old_key = l.key
        ldata = self.db.get_bytes(old_key)
        l.key = 'z1'
        self.db.set(l.key, ldata, encode_value=False)
        self.db.remove(old_key)

        self.assertEqual(l.pack(stop='k02'), 2)
        self.assertEqual(l.get_range(), ['foo', 'bar', 'i0', 'i1'])
        reset()

        self.assertEqual(l.pack(start='zz'), 0)
        self.assertEqual(l.pack(start='zz', stop='zzz'), 0)
        self.assertEqual(l.pack(start='a', stop='aa'), 0)
        self.assertEqual(l.pack(stop='aa'), 0)
        self.assertEqual(l.pack('k2', 'k4', 0), 0)
        self.assertEqual(l.get_range(), ['foo', 'bar'])

    def test_list_errors(self):
        l = self.db.List('l1')
        #self.db.set_bulk({'k%02d' % i: 'i%s' % i for i in range(10)})

        def _lua(cmd, data):
            with self.assertRaises(ProtocolError):
                self.db.script(cmd, data, encode_values=False,
                               decode_values=False)

        _lua('llpush', {})  # Missing key.
        _lua('llpush', {'key': 'l1'})  # Missing value.

        l.append('item-1')

        _lua('lremrange', {'key': 'l1', 'start': '1'})  # Invalid start idx.
        _lua('lremrange', {'key': 'l1', 'start': '0', 'stop': '2'})  # Stop.
        _lua('lset', {'key': 'l1', 'index': '2'})  # Missing value.

        self.assertEqual(list(l), ['item-1'])

    def test_large_values(self):
        n = 200
        h = self.db.Hash('h')
        data = {'k%064d' % i: 'v%01024d' % i for i in range(n)}
        self.assertEqual(h.set_bulk(data), n)
        self.assertEqual(h.get_all(), data)

        values = sorted(data.values())
        s = self.db.Set('s')
        self.assertEqual(s.add_bulk(values), n)
        self.assertEqual(s.members(), set(values))

        l = self.db.List('l')
        self.assertEqual(l.extend(values), n)
        self.assertEqual(l.get_range(), values)

        h.pack_values('lp')
        lp = self.db.List('lp')
        self.assertEqual(len(lp), n)

        s1 = self.db.Set('s1')
        s1.add_bulk(values)
        s1.remove_bulk(values[::3])

        s2 = self.db.Set('s2')
        s2.add_bulk(values)
        s2.remove_bulk(values[::4])

        self.assertEqual(len(s1), 133)
        self.assertEqual(len(s2), 150)

        si = self.db.Set('si')
        i = s1.intersection(s2, dest=si)
        self.assertEqual(len(si), 100)
        self.assertEqual(len(si), len(i))

        sd = self.db.Set('sd')
        d = s1.difference(s2, dest=sd)
        self.assertEqual(len(sd), 33)
        self.assertEqual(len(sd), len(d))

    def test_hash_pack_keys_values(self):
        h = self.db.Hash('h')
        h.update({'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})
        # h.pack_keys('hk')  # Un-testable with pickle serialization.
        self.assertEqual(h.pack_values('hv'), 3)

        # lk = self.db.List('hk')
        lv = self.db.List('hv')
        # self.assertEqual(sorted(lk.get_range()), ['k1', 'k2', 'k3'])
        self.assertEqual(sorted(lv.get_range()), ['v1', 'v2', 'v3'])

        h = self.db.Hash('h2')
        self.assertEqual(h.pack_values('hv2'), 0)
        self.assertFalse(self.db.exists('hv2'))

    def test_get_set_raw(self):
        hdata = {'k1': 'v1', 'k2': {'x1': 'y1', 'x2': 'y2'}, 'k3': 0}
        h = self.db.Hash('h')
        h.set_raw(hdata)
        self.assertEqual(h.get_raw(), hdata)
        self.assertEqual(h.get_all(), hdata)
        self.assertEqual(h['k1'], hdata['k1'])
        self.assertEqual(h['k2'], hdata['k2'])
        self.assertEqual(h['k3'], hdata['k3'])
        self.db.remove(h.key)
        self.assertEqual(h.get_raw(), None)

        ldata = ['i1', {'x1': 'y1', 'x2': 'y2'}, 3.34, None, 'i5']
        l = self.db.List('l')
        l.set_raw(ldata)
        self.assertEqual(l.get_raw(), ldata)
        self.assertEqual(list(l), ldata)
        for i in range(len(ldata)):
            self.assertEqual(l[i], ldata[i])
        self.db.remove(l.key)
        self.assertEqual(l.get_raw(), None)


class TestLuaContainersMultiDB(BaseLuaTestCase):
    server_kwargs = {
        'database': '%',
        'server_args': ['-scr', BaseLuaTestCase.lua_script, '*']}

    def test_hash_multidb(self):
        self.db.set_database(1)
        h = self.db.Hash('h1')
        h.update(k1='v1', k2='v2', k3='v3')
        self.assertEqual(h.get_all(), {'k1': 'v1', 'k2': 'v2', 'k3': 'v3'})
        self.assertEqual(h['k2'], 'v2')
        self.assertTrue('k1' in h)
        self.assertFalse('kx' in h)
        self.assertTrue(h.set('k1', 'v1-x'))
        self.assertFalse(h.setnx('k2', 'v2-x'))
        self.assertEqual(h.remove('k3'), 1)
        self.assertEqual(h.get_all(), {'k1': 'v1-x', 'k2': 'v2'})
        self.assertEqual(h.get_bulk(['k1', 'kx']), {'k1': 'v1-x'})
        self.assertEqual(len(h), 2)

        h2 = self.db.Hash('h1', db=0)
        self.assertEqual(len(h2), 0)

        lk = self.db.List('hk')
        lv = self.db.List('hv')
        self.assertEqual(h.pack_keys(lk.key), 2)
        self.assertEqual(h.pack_values(lv.key), 2)
        self.assertEqual(sorted(lk.get_range()), ['k1', 'k2'])
        self.assertEqual(sorted(lv.get_range()), ['v1-x', 'v2'])

        # Verify the key is in the correct database.
        keys = ('h1', 'hk', 'hv')
        for k in keys:
            self.assertFalse(self.db.exists(k, db=0))
            self.assertTrue(self.db.exists(k, db=1))

    def test_set_multidb(self):
        self.db.set_database(1)
        s = self.db.Set('s1')
        self.assertEqual(s.add_bulk(['k1', 'k2', 'k3']), 3)
        self.assertEqual(len(s), 3)
        self.assertEqual(s.remove('k2'), 1)
        self.assertEqual(s.members(), {'k1', 'k3'})
        self.assertTrue('k1' in s)
        self.assertFalse('k2' in s)
        self.assertEqual(len(s), 2)

        s2 = self.db.Set('s1', db=0)
        self.assertEqual(len(s2), 0)

        self.assertFalse(self.db.exists(s.key, db=0))
        self.assertTrue(self.db.exists(s.key, db=1))

    def test_list_multidb(self):
        self.db.set_database(1)
        l = self.db.List('l1')
        self.assertEqual(l.extend(['i2']), 1)
        self.assertEqual(l.appendleft('i1'), 2)
        self.assertEqual(l.append('i3'), 3)
        self.assertEqual(l.get_range(), ['i1', 'i2', 'i3'])
        self.assertEqual(len(l), 3)
        self.assertEqual(l[2], 'i3')
        self.assertRaises(IndexError, lambda: l[4])
        self.assertEqual(l.pop(1), 'i2')
        self.assertEqual(l.popright(), 'i3')
        self.assertEqual(l.insert(0, 'i0'), 2)
        self.assertEqual(len(l), 2)
        self.assertEqual(l.find('i1'), 1)
        self.assertEqual(l.rfind('i1'), 1)
        self.assertEqual(l.find('ix'), None)
        self.assertEqual(l.rfind('ix'), None)
        self.assertEqual(l.get_range(), ['i0', 'i1'])

        self.assertEqual(l.unpack(prefix='p:'), 2)
        lp = self.db.List('lp')
        self.assertEqual(lp.pack(start='p:', stop='q'), 2)
        self.assertEqual(lp.get_range(), ['i0', 'i1'])

        l2 = self.db.List('l1', db=0)
        self.assertEqual(len(l2), 0)

        for key in ('l1', 'lp'):
            self.assertFalse(self.db.exists(key, db=0))
            self.assertTrue(self.db.exists(key, db=1))


class TestLuaHexastore(BaseLuaTestCase):
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


class TestLuaQueue(BaseLuaTestCase):
    def test_queue(self):
        qa = self.db.Queue('qa')
        qb = self.db.Queue('qb')

        for i in range(20):
            qa.add('i%s' % i)
            qb.add('i%s' % (i % 4))

        self.assertEqual(len(qa), 20)
        self.assertEqual(len(qb), 20)

        self.assertEqual(qa.pop(), 'i0')
        self.assertEqual(qa.rpop(), 'i19')
        self.assertEqual(qa.pop(n=3), ['i1', 'i2', 'i3'])
        self.assertEqual(qa.rpop(n=3), ['i18', 'i17', 'i16'])
        self.assertEqual(qa.peek(n=3), ['i4', 'i5', 'i6'])
        self.assertEqual(qa.rpeek(n=3), ['i15', 'i14', 'i13'])

        # i0, i1, i2, i3 ... x5.
        self.assertEqual(qb.remove('i1', n=4), 4)
        self.assertEqual(qb.rremove('i2', n=4), 4)
        self.assertEqual(len(qb), 12)
        self.assertEqual(qb.peek(20), ['i0', 'i2', 'i3', 'i0', 'i3',
                                       'i0', 'i3', 'i0', 'i3', 'i0',
                                       'i1', 'i3'])
        self.assertEqual(qb.remove('i3', n=5), 5)
        self.assertEqual(qb.remove('i0', n=10), 5)
        self.assertEqual(qb.bpop(), 'i2')
        self.assertEqual(qb.bpop(), 'i1')
        self.assertEqual(len(qb), 0)

        self.assertEqual(qa.remove('i7'), 1)
        self.assertEqual(qa.remove('i7'), 0)
        self.assertEqual(qa.pop(n=5), ['i4', 'i5', 'i6', 'i8', 'i9'])

    def test_queue_bpop(self):
        qa = self.db.Queue('qa')
        qa.add('item')
        self.assertEqual(qa.bpop(), 'item')
        self.assertTrue(qa.bpop(timeout=0.1) is None)

    def test_queue_score_sorting(self):
        # See also TestLuaScheduler.test_lua_schedule.
        q = self.db.Queue('q')

        scores = [100, 10, 1000, 1, 0,
                  3,  -10, 5,    4, 2]
        for score in scores:
            q.add('i%s' % score, score)

        self.assertEqual(len(q), len(scores))

        # Sorted by score (priority), descending.
        self.assertEqual(q.peek(n=len(scores)), [
            'i1000', 'i100', 'i10', 'i5', 'i4',
            'i3', 'i2', 'i1', 'i0', 'i-10'])
        self.assertEqual(q.peek(), 'i1000')
        self.assertTrue(q.peek(min_score=1001) is None)

        self.assertEqual(q.pop(4, min_score=10), ['i1000', 'i100', 'i10'])
        self.assertEqual(q.pop(2, min_score=10), [])
        self.assertEqual(q.bpop(), 'i5')
        self.assertEqual(q.bpop(min_score=3), 'i4')

        self.assertEqual(q.rpeek(3), ['i-10', 'i0', 'i1'])
        self.assertEqual(q.rpeek(2, min_score=0), ['i0', 'i1'])
        self.assertEqual(q.rpop(2, min_score=1), ['i1', 'i2'])

        self.assertEqual(len(q), 3)
        self.assertEqual(q.peek(4), ['i3', 'i0', 'i-10'])
        self.assertEqual(q.peek(4, min_score=0), ['i3', 'i0'])
        self.assertEqual(q.peek(4, min_score=-9), ['i3', 'i0'])

        self.assertEqual(q.pop(2, min_score=0), ['i3', 'i0'])
        self.assertEqual(q.peek(), q.rpeek())
        self.assertEqual(q.pop(), 'i-10')
        self.assertEqual(len(q), 0)

    def test_mix_score_default(self):
        # Test no explicit score defaults to zero.
        q = self.db.Queue('q')
        q.add('ix')
        q.add('iy')
        q.add('iz', 1)
        self.assertTrue(q.peek(), 'iz')
        self.assertTrue(q.rpeek(), 'iy')
        self.assertEqual(len(q), 3)
        self.assertEqual(q.peek(10), ['iz', 'ix', 'iy'])
        self.assertEqual(q.peek(10, 1), ['iz'])

        self.assertEqual(q.pop(), 'iz')
        self.assertEqual(q.rpop(), 'iy')

        self.assertTrue(q.peek() == q.rpeek() == 'ix')
        self.assertTrue(q.peek(min_score=1) is None)
        self.assertTrue(q.rpeek(min_score=1) is None)
        self.assertEqual(q.remove('ix', min_score=1), 0)
        self.assertEqual(len(q), 1)
        self.assertEqual(q.remove('ix', min_score=-1), 1)
        self.assertEqual(len(q), 0)

    def test_queue_remove_score(self):
        # Test no explicit score defaults to zero, and test remove() with a
        # minimum score.
        q = self.db.Queue('q')
        q.add('x')
        q.add('x', 3)
        q.extend(['y', 'x', 'z'])
        q.extend(['y', 'z'], 2)
        q.add('y', 2)
        q.add('z', 1)

        # x(3), y(2), z(2), y(2), z(1), x(0), y(0), x(0), z(0)
        self.assertEqual(len(q), 9)
        self.assertEqual(q.peek(9), ['x', 'y', 'z', 'y', 'z',
                                     'x', 'y', 'x', 'z'])

        self.assertEqual(q.remove('x', n=2, min_score=3), 1)
        self.assertEqual(q.rremove('y', n=1, min_score=1), 1)
        self.assertEqual(q.rremove('z', n=2, min_score=0), 2)

        # y(2), z(2), x(0), y(0), x(0).
        self.assertEqual(len(q), 5)
        self.assertEqual(q.peek(5), ['y', 'z', 'x', 'y', 'x'])

        self.assertEqual(q.rremove('x', min_score=-1), 2)
        self.assertEqual(q.rremove('y', min_score=1), 1)

        # z(2), y(0).
        self.assertEqual(len(q), 2)
        self.assertEqual(q.peek(2), ['z', 'y'])

        # Ordinary remove works fine regardless of score.
        self.assertEqual(q.remove('z'), 1)
        self.assertEqual(q.remove('y'), 1)

    def test_queue_set_priority(self):
        q = self.db.Queue('q')

        # Add 3 items with priority=0.
        q.extend(['i0', 'i1', 'i2'])
        self.assertEqual(q.peek(3), ['i0', 'i1', 'i2'])
        self.assertEqual(q.rpeek(3), ['i2', 'i1', 'i0'])

        self.assertEqual(q.set_priority('i1', 1), 1)
        self.assertEqual(len(q), 3)
        self.assertEqual(q.peek(3), ['i1', 'i0', 'i2'])

        self.assertEqual(q.set_priority('i2', 2), 1)
        self.assertEqual(q.set_priority('i2', 2), 0)
        self.assertEqual(q.set_priority('i0', 0), 0)
        self.assertEqual(q.set_priority('i0', -1), 1)
        self.assertEqual(len(q), 3)
        self.assertEqual(q.peek(3), ['i2', 'i1', 'i0'])
        self.assertEqual(q.rpeek(3), ['i0', 'i1', 'i2'])

        self.assertEqual(q.peek(3, 0), ['i2', 'i1'])
        self.assertEqual(q.rpeek(3, 0), ['i1', 'i2'])
        self.assertEqual(q.peek(3, 2), ['i2'])
        self.assertEqual(q.rpeek(3, 2), ['i2'])

    def test_queue_transfer(self):
        qa, qb, qc = [self.db.Queue(k) for k in ('qa', 'qb', 'qc')]
        def assertQ(a=None, b=None, c=None):
            self.assertEqual(qa.peek(10), a or [])
            self.assertEqual(qb.peek(10), b or [])
            self.assertEqual(qc.peek(10), c or [])

        qb.extend(['i0', 'i1', 'i2', 'i3'])
        self.assertEqual(qb.transfer(qa, 2), ['i0', 'i1'])
        assertQ(['i0', 'i1'], ['i2', 'i3'], [])

        self.assertEqual(qb.transfer(qc, 1), 'i2')
        assertQ(['i0', 'i1'], ['i3'], ['i2'])

        self.assertEqual(qc.transfer('qa', 2), ['i2'])
        assertQ(['i0', 'i1', 'i2'], ['i3'], [])

        self.assertEqual(qc.transfer('qb', 1), None)
        self.assertEqual(qc.transfer('qb', 2), [])
        assertQ(['i0', 'i1', 'i2'], ['i3'], [])

        self.assertEqual(qb.transfer(qa), 'i3')
        assertQ(['i0', 'i1', 'i2', 'i3'], [], [])

        self.assertEqual(qa.rpop(2), ['i3', 'i2'])

        # Verify scores are preserved.
        for i in range(5, 0, -1):
            qb.add('i-%s' % i, i)  # i-5, i-4, i-3, i-2, i-1.
        assertQ(['i0', 'i1'], ['i-5', 'i-4', 'i-3', 'i-2', 'i-1'], [])

        self.assertEqual(qb.transfer(qa, 2), ['i-5', 'i-4'])
        self.assertEqual(qb.transfer(qc, 2), ['i-3', 'i-2'])
        assertQ(['i-5', 'i-4', 'i0', 'i1'], ['i-1'], ['i-3', 'i-2'])

        self.assertEqual(qa.transfer(qc, 3), ['i-5', 'i-4', 'i0'])
        assertQ(['i1'], ['i-1'], ['i-5', 'i-4', 'i-3', 'i-2', 'i0'])

        self.assertEqual(qc.transfer(qb, 1000),
                         ['i-5', 'i-4', 'i-3', 'i-2', 'i0'])
        assertQ(['i1'], ['i-5', 'i-4', 'i-3', 'i-2', 'i-1', 'i0'], [])

        self.assertEqual(qa.transfer(qb), 'i1')
        assertQ([], ['i-5', 'i-4', 'i-3', 'i-2', 'i-1', 'i0', 'i1'], [])


class TestLuaSerializers(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {
        'serializer': KT_JSON,
        'database': '%',
        'server_args': ['-scr', lua_script]}

    def test_queue_pickle(self):
        q = self.db.Queue('qa')
        q.add({'key': 'i0'})
        q.extend([{'key': 'i%s' % i} for i in range(1, 10)])

        self.assertEqual(q.pop(), {'key': 'i0'})
        self.assertEqual(q.rpop(2), [{'key': 'i9'}, {'key': 'i8'}])

        self.assertEqual(q.peek(n=2), [{'key': 'i1'}, {'key': 'i2'}])
        self.assertEqual(q.rpeek(), {'key': 'i7'})

        self.assertEqual(q.remove({'key': 'i2'}), 1)
        self.assertEqual(q.remove({'key': 'i2'}), 0)
        self.assertEqual(q.rremove({'key': 'i6'}), 1)
        self.assertEqual(q.rremove({'key': 'i6'}), 0)

        self.assertEqual(len(q), 5)

        self.assertEqual(q.bpop(), {'key': 'i1'})
        self.assertEqual(q.bpop(), {'key': 'i3'})

        next_key = self.db.match_prefix('qa\t')[0]
        raw_data = self.db.get_bytes(next_key)
        self.assertEqual(raw_data, b'{"key":"i4"}')

        self.assertEqual(q.pop(n=100), [
            {'key': 'i4'}, {'key': 'i5'}, {'key': 'i7'}])


class TestLuaSchedule(BaseTestCase):
    lua_script = os.path.join(BaseTestCase.lua_path, 'kt.lua')
    server_kwargs = {
        'serializer': KT_PICKLE,
        'database': '%',
        'server_args': ['-scr', lua_script]}

    def test_lua_schedule(self):
        s = self.db.Schedule('sched')
        nums = [100, 10, 1000, 1, 3, 5, 4, 20, 2]
        for num in nums:
            s.add('i%s' % num, num)
        self.assertEqual(len(s), len(nums))

        self.assertEqual(s.read(n=1), ['i1'])
        self.assertEqual(s.read(4), ['i2', 'i3', 'i4'])
        self.assertEqual(s.read(100, n=2), ['i5', 'i10'])
        self.assertEqual(len(s), 3)
        self.assertEqual(s.read(100, n=4), ['i20', 'i100'])
        self.assertEqual(s.read(), ['i1000'])
        self.assertEqual(len(s), 0)
        self.assertEqual(s.clear(), 1)

    def test_lua_samescore(self):
        s = self.db.Schedule('sched')

        for i in reversed(range(1, 4)):
            s.add('ia-%s' % i, 1)
            s.add('ib-%s' % i, 2)

        self.assertEqual(s.read(n=2), ['ia-3', 'ia-2'])
        self.assertEqual(s.read(n=2), ['ia-1', 'ib-3'])
        self.assertEqual(s.read(1), [])
        self.assertEqual(s.read(), ['ib-2', 'ib-1'])


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

    def test_pool_age_tracking(self):
        self.db.close_all()  # Ensure no open connections.

        p = self.db.pool
        self.assertEqual(p.stats, (0, 0, 0, 0))
        s1 = p.create_socket()
        s2 = p.create_socket()

        # Configure with two sockets, one expires in 200s, one in 600s.
        now = time.time()
        s1_time = now - 3400
        s2_time = now - 3000
        p.free = [(s1_time, s1), (s2_time, s2)]

        # Checking out a socket gives us the oldest one first.
        s = p.checkout()
        self.assertTrue(s is s1)

        # Pool indicates that we have one in use and one available.
        self.assertEqual(p.stats, (1, 1, 0, 0))
        p.checkin(s)
        self.assertEqual(p.stats, (0, 2, 0, 0))

        # Pool retains the timestamp for the socket creation.
        self.assertEqual(p.free, [(s1_time, s1), (s2_time, s2)])

        # We get s1 again, as it is still the oldest.
        s = p.checkout()
        self.assertTrue(s is s1)

        # Make socket ready for closing.
        p.in_use[s] = now - 3601
        self.assertFalse(s.is_closed)
        p.checkin(s)

        # The socket was closed and is not recycled.
        self.assertTrue(s.is_closed)
        self.assertEqual(p.stats, (0, 1, 0, 0))

        # Manually close the socket and verify it is not recycled.
        s = p.checkout()
        self.assertTrue(s is s2)
        s.close()
        p.checkin(s)

        self.assertEqual(p.stats, (0, 0, 0, 0))


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


class TestConnectionError(unittest.TestCase):
    def setUp(self):
        if sys.version_info[0] > 2:
            warnings.filterwarnings(action='ignore', message='unclosed',
                                    category=ResourceWarning)

        self.server = EmbeddedServer(database=':')
        self.server.run()
        self.db = self.server.client

    def tearDown(self):
        self.server.stop(wait=True)
        self.db.close_all()

    def test_connection_error(self):
        self.assertEqual(self.db.set('k1', 'v1'), 1)
        self.assertEqual(self.db.get('k1'), 'v1')

        # Restart the server.
        self.server.stop(wait=True)
        self.server.run()

        self.assertRaises(ServerConnectionError, self.db.get, 'k1')
        self.assertTrue(self.db.get('k1') is None)


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
