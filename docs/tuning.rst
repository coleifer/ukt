.. _tuning:

Tuning Kyoto Tycoon
===================

These are notes based on the documentation and distilled into something
hopefully a bit easier to follow.

Supported by all databases:

* ``log`` - path to logfile
* ``logkinds`` - debug, info, warn or error
* ``logpx`` - prefix for each log message

Other options:

* ``bnum`` - number of buckets in the hash table
* ``capcnt`` - set capacity by record number
* ``capsiz`` - set capacity by memory usage
* ``msiz`` - size of internal memory-mapped region, typically should be set to
  a significant percentage of total memory (e.g., if you have 16g set to 12g).
* ``psiz`` - page size, defaults to 8192
* ``pccap`` - page-cache capacity
* ``opts`` - s=small, l=linear, c=compress - l=linked-list for hash collisions.
* ``zcomp`` - compression algorithm: zlib, def (deflate), gz, lzo, lzma or arc
* ``zkey`` - cipher key for compression (?)
* ``rcomp`` - comparator function: lex, dec (decimal), lexdesc, decdesc
* ``apow`` - record alignment, as power of 2, e.g. apow=3 == 8 bytes.
* ``fpow`` - maximum elements in the free-block pool
* ``dfunit`` - unit step for auto-defragmentation, default=0 (disabled).

Databases and available parameters
----------------------------------

* Stash (``:``): bnum
* Cache hash (``*``): opts, bnum, zcomp, capcnt, capsiz, zkey
* Cache tree (``%``): opts, bnum, zcomp, zkey, psiz, rcomp, pccap
* File hash (``.kch``): opts, bnum, apow, fpow, msiz, dfunit, zcomp, zkey
* File tree (``.kct``): opts, bnum, apow, fpow, msiz, dfunit, zcomp, zkey, psiz
* Dir hash (``.kcd``): opts, zcomp, zkey
* Dir tree (``.kcf``): opts, zcomp, zkey, psiz, rcomp, pccap
* Plain-text (``.kcx``): n/a
* Prototype hash (``-``): n/a, not recommended (std::unorderedmap)
* Prototype tree (``+``): n/a, not recommended (std::map)

Information available here: https://fallabs.com/kyotocabinet/spex.html#tips

When choosing a database:

* Do you need persistence? If not, use one of the in-memory databases.
* Are the order of keys important? If so, use one of the tree databases.
* Do you want LRU eviction with an upper-bound of memory usage? Use cache hash.
* Are your values very large? Consider using the filesystem or the directory
  hash/tree database.

In-memory databases:

* time efficiency: Cache hash > Stash > Proto hash > Proto tree > Cache tree
* space efficiency: Cache tree > Stash > Cache hash > Proto hash > Proto tree

Persistent databases:

* time efficiency: Hash > Tree > Dir hash > Dir tree
* space efficiency: Tree > Hash > Dir tree > Dir hash

Stash database
^^^^^^^^^^^^^^

Stash database is stored in memory and is a little bit more efficient than the
cache hash (``*``), however it handles eviction slightly differently. The cache
hash retains metadata so that it is able to do LRU eviction, whereas the stash
database evicts random records.

* ``bnum`` - default is ~1M, should be 80%-400% of total records

CacheHashDB
^^^^^^^^^^^

Stored in-memory and supports LRU eviction, uses a doubly-linked hash map.

* ``bnum``: default ~1M. Should be 50% - 400% of total records. Collision
  chaining is binary search
* ``opts``: useful to reduce memory at expense of time effciency. Use compression
  if the key and value of each record is greater-than 1KB
* ``capcnt`` and/or ``capsiz``: keep memory usage constant by expiring old
  records.
* supports compression, which is recommended when values are larger than 1KB.

CacheTreeDB
^^^^^^^^^^^

Inherits all tuning options from the CacheHashDB, since each node of the btree
is serialized as a page-buffer and treated as a record in the cache hash db.

* ``psiz``: default is 8192
* ``pccap``: page-cache capacity, default is 64MB
* ``rcomp``: comparator, default is lexical ordering

HashDB
^^^^^^

On-disk hash table.

* ``bnum``: default ~1M. Suggested ratio is twice the total number of records,
  but can be anything from 100% - 400%.
* ``msiz``: Size of internal memory-mapped region. Default is 64MB. It is very
  advisable to set this to a value larger than the expected size of the
  database, e.g. 12G if you have 16G of memory available.
* ``dfunit``: Unit step number of auto-defragmentation. Auto-defrag is disabled
  by default.
* ``apow``: Power of the alignment of record size. Default=3, so the address of
  each record is aligned to a multiple of 8 (``2^3``) bytes.
* ``fpow``: Power of the capacity of the free block pool. Default=10, rarely
  needs to be modified.

apow, fpow, opts and bnum *must* be specified before a DB is opened and
cannot be changed after the fact.

TreeDB
^^^^^^

Inherits tuning parameters from the HashDB, as the B-Tree is implemented on top
of the file hash database. Supports the following additional tuning parameters:

* ``bnum``: default 64K. Bucket number should be calculated by the number of
  pages, such that the bucket number is 10% of the total record count.
* ``pccap``: page-cache capacity, default is 64MB. If there is additional RAM,
  this can be increased, but it is better to assign RAM using the internal
  memory-mapped region using the ``msiz`` parameter.
* ``psiz``: default is 8192, specified before opening db and cannot be changed.
* ``rcomp``: record comparator, default is lexical

Unlike the HashDB, the default alignment power (``apow``) is 256 (2^8), and the
default bucket number is 64K.

Server configuration
--------------------

Complete list of available options for running `ktserver <http://alticelabs.github.io/kyoto/kyototycoon/doc/command.html#ktserver>`_.

Note that the durability options may have a significant impact on performance:

* ``-oat`` - automatic transactions
* ``-asi`` / ``-uasi`` - automatic synchronization of database and update logs
* ``-ash`` - physical synchronization

Also refer to the `"tips" document <https://fallabs.com/kyototycoon/spex.html#tips>`_,
which covers things like binary logging, snapshots, replication, etc.

Notes from alticelabs `readme <https://github.com/alticelabs/kyoto>`_:

* Don't use the ``capsiz`` option with on-disk databases as the server will
  temporarily stop responding to free up space when the maximum capacity is
  reached. In this case, try to keep the database size under control using
  auto-expiring keys instead.
* On-disk databases are sensitive to disk write performance (impacting record
  updates as well as reads). Enabling transactions and/or synchronization makes
  this worse, as does increasing the number of buckets for hash databases
  (larger structures to write). Having a disk controller with some kind of
  battery-backed write-cache makes these issues mute.
* Choose your on-disk database tuning options carefully and don't tune unless
  you need to. Some options can be modified by a simple restart of the server
  (e.g. ``pccap``, ``msiz``) but others require creating the database from
  scratch (e.g.  ``bnum``, ``opts=c``).
* Make sure you have enough disk space to store your on-disk databases as they
  grow. The server uses ``mmap()`` for file access and handles out-of-space
  conditions by terminating immediately. The database should still be
  consistent if this happens, so don't fret too much about it.
* The unique server ID (``-sid``) is used to break replication loops (a server
  instance ignores keys with its own SID). Keep this in mind when restoring
  failed master-master instances. The documentation recommends always choosing
  a new SID but this doesn't seem a good idea in this case. If the existing
  master still has keys from the failed master with the old SID pending
  replication, the new master with a new SID will propagate them back.

Examples:

Standalone b-tree database with compression and binary logging enabled. The
``pccap=256m`` option increases the default page-cache memory to 256mb:

.. code-block:: console

    $ /usr/local/bin/ktserver -ls -th 16 -port 1978 -pid /data/kyoto/kyoto.pid \
                              -log /data/kyoto/ktserver.log -oat -uasi 10 -asi 10 -ash \
                              -sid 1001 -ulog /data/kyoto/db -ulim 104857600 \
                              '/data/kyoto/db/db.kct#opts=c#pccap=256m#dfunit=8'

If you have a good idea of how many objects you are storing, you can use a
persistent hash. The ``bnum=1m`` configures 1 million hash buckets (about 2x
the number of expected keys), and ``msiz=256m`` sets the size of the
memory-mapped region (larger is better, depending on availability of RAM).

.. code-block:: console

    $ /usr/local/bin/ktserver -ls -th 16 -port 1978 -pid /data/kyoto/kyoto.pid \
                              -log /data/kyoto/ktserver.log -oat -uasi 10 -asi 10 -ash \
                              -sid 1001 -ulog /data/kyoto/db -ulim 104857600 \
                              '/data/kyoto/db/db.kch#opts=l#bnum=1000000#msiz=256m#dfunit=8'

In-memory cache limited to 256mb with LRU eviction:

.. code-block:: console

    $ /usr/local/bin/ktserver -log /var/log/ktserver.log -ls '*#bnum=100000#capsiz=256m'

To enable simultaneous support for the memcached protocol, use the ``-plsv``
and ``-plex`` options. The ``opts=f`` enables flags support for memcached,
which are stored as the last 4 bytes of the value (take care when mixing
protocols!).

.. code-block:: console

    $ /usr/local/bin/ktserver -log /var/log/ktserver.log -ls \
                              -plsv /usr/local/libexec/ktplugservmemc.so \
                              -plex 'port=11211#opts=f' \
                              '*#bnum=100000#capsiz=256m'
