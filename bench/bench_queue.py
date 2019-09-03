#!/usr/bin/env python

from contextlib import contextmanager
import os
import sys
import time

srcdir = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, srcdir)

from ukt import *


script = os.path.join(srcdir, 'scripts/kt.lua')

server = EmbeddedServer(database='%', server_args=['-scr', script],
                        quiet=False)
server.run()

db = server.client
queue = db.Queue('qa')


N = 100000
CHUNKSIZE = 10


def enqueue():
    for i in range(0, N, CHUNKSIZE):
        items = ['i%05d' % j for j in range(i, i + CHUNKSIZE)]
        queue.extend(items)


def dequeue():
    for i in range(0, N, CHUNKSIZE):
        data = queue.pop(CHUNKSIZE)
        assert data == ['i%05d' % j for j in range(i, i + CHUNKSIZE)]


def enqueue_priority():
    for i in range(0, N, CHUNKSIZE):
        items = ['i%05d' % j for j in range(i, i + CHUNKSIZE)]
        queue.extend(items, i)


def dequeue_priority():
    for i in range(0, N, CHUNKSIZE):
        data = queue.pop(CHUNKSIZE)
        s = N - i - CHUNKSIZE
        assert data == ['i%05d' % j for j in range(s, s + CHUNKSIZE)]


@contextmanager
def timed(s):
    start = time.time()
    yield
    duration = time.time() - start
    op_s = (N / CHUNKSIZE) / duration
    print('%0.2f op/s %s' % (op_s, s))

db.clear()

with timed('enqueueing'):
    enqueue()

with timed('dequeueing'):
    dequeue()

with timed('enqueue priority'):
    enqueue_priority()

with timed('dequeue priority'):
    dequeue_priority()

db.clear()
