.. _api:

API
===

Serializers
-----------

.. py:data:: KT_BINARY

    Default value serialization. Serializes values as UTF-8 byte-strings and
    deserializes to unicode.

.. py:data:: KT_JSON

    Serialize values as JSON (encoded as UTF-8).

.. py:data:: KT_MSGPACK

    Uses ``msgpack`` to serialize and deserialize values.

.. py:data:: KT_NONE

    No serialization or deserialization. Values must be byte-strings.

.. py:data:: KT_PICKLE

    Serialize and deserialize using Python's pickle module.


Kyoto Tycoon client
-------------------

.. py:class:: KyotoTycoon(host='127.0.0.1', port=1978, timeout=None, default_db=0, decode_keys=True, serializer=None, encode_value=None, decode_value=None, max_age=3600)

    :param str host: server host.
    :param int port: server port.
    :param int timeout: socket timeout for database connection.
    :param int default_db: default database index.
    :param bool decode_keys: decode keys as utf8-encoded unicode.
    :param serializer: serialization method to use for storing/retrieving
        values. Default is ``KT_BINARY``, which treats values as utf8-encoded
        unicode. ``KT_NONE`` disables all serialization, or use one of
        ``KT_JSON``, ``KT_MSGPACK`` or ``KT_PICKLE``.
    :param encode_value: custom serializer for encoding values as bytestrings.
    :param decode_value: custom deserializer for decoding bytestrings.
    :param int max_age: max idle time for socket in connection pool.

    Client for interacting with Kyoto Tycoon database.

    .. py:method:: set_database(db)

        :param int db: database index.

        Set the default database for the client. The Kyoto Tycoon server can be
        run by specifying multiple database paths. This method allows you to
        specify which database the client communicates with by default, though
        most methods accept a ``db`` parameter which can override the default
        for a given call.

    .. py:method:: close_all()

        :return: number of connections that were closed.

        Close all connections in the connection pool. The pool maintains two
        sets of connections:

        * Binary protocol connections.
        * HTTP client connections for the HTTP API.

        Since the binary protocol only implements a subset of the total
        commands, *ukt* will transparently use the appropriate connection type
        for a given method.

    .. py:method:: serialize_dict(d, encode_values=True)

        :param dict d: arbitrary data.
        :param bool encode_values: serialize the values using the configured
            serialization scheme.
        :return: serialized data.

        Serialize a ``dict`` as a sequence of bytes compatible with KT's
        built-in lua ``mapdump`` function and the :py:class:`Hash` container
        type.

    .. py:method:: deserialize_dict(data, decode_values=True)

        :param bytes data: serialized data.
        :param bool decode_values: decode values using the configured
            serialization scheme.
        :return: data ``dict``.

        Deserialize a sequence of bytes into a dictionary, optionally decoding
        the values as unicode strings. Compatible with KT's built-in lua
        ``mapload`` function and the :py:class:`Hash` container type.

    .. py:method:: serialize_list(l, encode_values=True)

        :param list l: arbitrary data.
        :param bool encode_values: serialize the values using the configured
            serialization scheme.
        :return: serialized data.

        Serialize a ``list`` as a sequence of bytes compatible with KT's
        built-in lua ``arraydump`` function and the :py:class:`List` container
        type.

    .. py:method:: deserialize_list(data, decode_values=True)

        :param bytes data: serialized data.
        :param bool decode_values: decode values using the configured
            serialization scheme.
        :return: data ``list``.

        Deserialize a a sequence of bytes into a list, optionally decoding the
        values as unicode strings. Compatible with KT's built-in lua
        ``arrayload`` function and the :py:class:`List` container type.

    .. py:method:: get_bulk(keys, db=None, decode_values=True)

        :param list keys: keys to retrieve.
        :param int db: database index.
        :param bool decode_values: decode values using the configured
            serialization scheme.
        :return: result dictionary

        Efficiently retrieve multiple key/value pairs from a database. If a
        key does not exist, it will not be present in the result dictionary.

    .. py:method:: get_bulk_details(db_key_list, decode_values=True)

        :param list db_key_list: a list of ``(db, key)`` tuples to fetch.
        :param bool decode_values: decode values using the configured
            serialization scheme.
        :return: list of tuples: ``(db index, key, value, expire time)``

        Like :py:meth:`~KyotoTycoon.get_bulk`, but the return value is a list
        of tuples with additional information for each key. Since each key is
        of the form ``(db, key)``, this method can be used to efficiently fetch
        records from multiple databases.

    .. py:method:: get(key, db=None, decode_value=True)

        :param str key: key to look-up
        :param int db: database index
        :param bool decode_value: decode value using serializer.
        :return: deserialized value or ``None`` if key does not exist.

        Fetch and (optionally) deserialize the value for the given key.

    .. py:method:: get_bytes(key, db=None)

        :param str key: key to look-up
        :param int db: database index
        :return: raw bytestring value or ``None`` if key does not exist.

        Fetch the value for the given key. The resulting value will **not**
        be deserialized.

    .. py:method:: set_bulk(data, db=None, expire_time=None, no_reply=False, encode_values=True)

        :param dict data: mapping of key/value pairs to set.
        :param int db: database index
        :param int expire_time: expiration time in seconds
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :param bool encode_values: serialize the values using the configured
            serialization scheme (e.g., ``KT_MSGPACK``).
        :return: number of keys that were set, or ``None`` if ``no_reply``.

        Efficiently set multiple key/value pairs. If given, the provided ``db``
        and ``expire_time`` values will be used for all key/value pairs being
        set.

    .. py:method:: set_bulk_details(data, no_reply=False, encode_values=True)

        :param list data: a list of 4-tuples: ``(db, key, value, expire-time)``
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :param bool encode_values: serialize the values using the configured
            serialization scheme (e.g., ``KT_MSGPACK``).
        :return: number of keys that were set, or ``None`` if ``no_reply``.

        Efficiently set multiple key/value pairs. Unlike
        :py:meth:`~KyotoTycoon.set_bulk`, this method can be used to set
        key/value pairs in multiple databases in a single call, and each key
        can specify its own expire time.

    .. py:method:: set(key, value, db=None, expire_time=None, no_reply=False, encode_value=True)

        :param str key: key to set.
        :param value: value to store.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :param bool encode_value: encode value using serializer.
        :return: number of rows set (1)

        Set a single key/value pair.

    .. py:method:: set_bytes(key, value, db=None, expire_time=None, no_reply=False)

        :param str key: key to set.
        :param bytes value: raw bytes to store.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of rows set (1)

        Set a single key/value pair, without serializing the value.

    .. py:method:: remove_bulk(keys, db=None, no_reply=False)

        :param list keys: list of keys to remove
        :param int db: database index
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of keys that were removed

        Remove multiple keys from a database in a single operation.

    .. py:method:: remove_bulk_details(db_key_list, no_reply=False)

        :param db_key_list: a list of 2-tuples to retrieve: ``(db index, key)``
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of keys that were removed

        Like :py:meth:`~KyotoTycoon.remove_bulk`, but allows keys to be removed
        from multiple databases in a single call. The input is a list of
        ``(db, key)`` tuples.

    .. py:method:: remove(key, db=None, no_reply=False)

        :param str key: key to remove
        :param int db: database index
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of rows removed

        Remove a single key from the database.

    .. py:method:: script(name, data=None, no_reply=False, encode_values=True, decode_values=True)

        :param str name: name of lua function to call.
        :param dict data: mapping of key/value pairs to pass to lua function.
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :param bool encode_values: serialize values passed to lua function.
        :param bool decode_values: deserialize values returned by lua function.
        :return: dictionary of key/value pairs returned by function.

        Execute a lua function. Kyoto Tycoon lua extensions accept arbitrary
        key/value pairs as input, and return a result dictionary. If
        ``encode_values`` is ``True``, the input values will be serialized.
        Likewise, if ``decode_values`` is ``True`` the values returned by the
        Lua function will be deserialized using the configured serializer.

    .. py:method:: raw_script(name, data=None, no_reply=False)

        :param str name: name of lua function to call.
        :param dict data: mapping of key/value pairs to pass to lua function.
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: dictionary of key/value pairs returned by function.

        Execute a lua function and return the result with no post-processing or
        serialization.

    .. py:method:: report()

        :return: status fields and values
        :rtype: dict

        Obtain report on overall status of server, including all databases.

    .. py:method:: status(db=None)

        :param int db: database index
        :return: status fields and values
        :rtype: dict

        Obtain status information from the server about the selected database.

    .. py:method:: list_databases()

        :return: a list of ``(database path, status dict)`` for each configured
            database.

        Return the list of databases and their status information.

    .. py:attribute:: databases

        Returns the list of paths for the configured databases.

    .. py:method:: clear(db=None)

        :param int db: database index
        :return: boolean indicating success

        Remove all keys from the database.

    .. py:method:: synchronize(hard=False, command=None, db=None)

        :param bool hard: perform a "hard" synchronization.
        :param str command: command to execute after synchronization.
        :param int db: database index.
        :return: boolean indicating success.

        Synchronize the database, optionally executing the given command upon
        success. This can be used to create hot backups, for example.

    .. py:method:: add(key, value, db=None, expire_time=None, encode_value=True)

        :param str key: key to add.
        :param value: value to store.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool encode_value: serialize the value using the configured
            serialization method.
        :return: boolean indicating if key could be added or not.
        :rtype: bool

        Add a key/value pair to the database. This operation will only succeed
        if the key does not already exist in the database.

    .. py:method:: replace(key, value, db=None, expire_time=None, encode_value=True)

        :param str key: key to replace.
        :param value: value to store.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool encode_value: serialize the value using the configured
            serialization method.
        :return: boolean indicating if key could be replaced or not.
        :rtype: bool

        Replace a key/value pair to the database. This operation will only
        succeed if the key alreadys exist in the database.

    .. py:method:: append(key, value, db=None, expire_time=None, encode_value=True)

        :param str key: key to append value to.
        :param value: data to append.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool encode_value: serialize the value using the configured
            serialization method.
        :return: boolean indicating if value was appended.
        :rtype: bool

        Appends data to an existing key/value pair. If the key does not exist,
        this is equivalent to :py:meth:`~KyotoTycoon.set`.

    .. py:method:: increment(key, n=1, orig=None, db=None, expire_time=None)

        :param str key: key to increment.
        :param int n: value to add.
        :param int orig: default value if key does not exist.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :return: new value at key.
        :rtype: int

        Increment the value stored in the given key.

    .. py:method:: increment_double(key, n=1., orig=None, db=None, expire_time=None)

        :param str key: key to increment.
        :param float n: value to add.
        :param float orig: default value if key does not exist.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :return: new value at key.
        :rtype: float

        Increment the floating-point value stored in the given key.

    .. py:method:: cas(key, old_val, new_val, db=None, expire_time=None, encode_value=True)

        :param str key: key to append value to.
        :param old_val: original value to test.
        :param new_val: new value to store.
        :param int db: database index.
        :param int expire_time: expiration time in seconds.
        :param bool encode_value: serialize the old and new values using the
            configured serialization method.
        :return: boolean indicating if compare-and-swap succeeded.
        :rtype: bool

        Perform an atomic compare-and-set the value stored at a given key.

    .. py:method:: exists(key, db=None)

        :param str key: key to test.
        :param int db: database index.
        :return: boolean indicating if key exists.

        Return whether or not the given key exists in the database.

    .. py:method:: length(key, db=None)

        :param str key: key.
        :param int db: database index.
        :return: length of the value in bytes, or ``None`` if not found.

        Return the length of the raw value stored at the given key. If the key
        does not exist, returns ``None``.

    .. py:method:: seize(key, db=None, decode_value=True)

        :param str key: key to remove.
        :param int db: database index.
        :param bool decode_value: deserialize the value using the configured
            serialization method.
        :return: value stored at given key or ``None`` if key does not exist.

        Perform atomic get-and-remove the value stored in a given key. This
        method is also available as :py:meth:`KyotoTycoon.pop` if that's easier
        to remember.

    .. py:method:: vacuum(step=0, db=None)

        :param int step: number of steps, default is 0
        :param int db: database index
        :return: boolean indicating success

        Vacuum the database.

    .. py:method:: match_prefix(prefix, max_keys=None, db=None)

        :param str prefix: key prefix to match.
        :param int max_keys: maximum number of results to return (optional).
        :param int db: database index.
        :return: list of keys that matched the given prefix.
        :rtype: list

        Return sorted list of keys that match the given prefix.

    .. py:method:: match_regex(regex, max_keys=None, db=None)

        :param str regex: regular-expression to match
        :param int max_keys: maximum number of results to return (optional)
        :param int db: database index
        :return: list of keys that matched the given regular expression.
        :rtype: list

        Return sorted list of keys that match the given regular expression.

    .. py:method:: match_similar(origin, distance=None, max_keys=None, db=None)

        :param str origin: source string for comparison
        :param int distance: maximum edit-distance for similarity (optional)
        :param int max_keys: maximum number of results to return (optional)
        :param int db: database index
        :return: list of keys that were within a certain edit-distance of origin
        :rtype: list

        Return sorted list of keys that are within a given edit distance from
        a string.

    .. py:method:: ulog_list()

        :return: a list of 3-tuples describing the files in the update log.

        Returns a list of metadata about the state of the update log. For each
        file in the update log, a 3-tuple is returned. For example:

        .. code-block:: pycon

            >>> kt.ulog_list()
            [('/var/lib/database/ulog/kt/0000000037.ulog',
              '67150706',
              datetime.datetime(2019, 1, 4, 1, 28, 42, 43000)),
             ('/var/lib/database/ulog/kt/0000000038.ulog',
              '14577366',
              datetime.datetime(2019, 1, 4, 1, 41, 7, 245000))]

    .. py:method:: ulog_remove(max_dt)

        :param datetime max_dt: maximum datetime to preserve
        :return: boolean indicating success

        Removes all update-log files older than the given datetime.

    .. py:method:: count(db=None)

        :param db: database index
        :type db: int or None
        :return: total number of keys in the database.
        :rtype: int

        Count total number of keys in the database.

    .. py:method:: size(db=None)

        :param db: database index
        :type db: int or None
        :return: size of database in bytes.

        Property which exposes the size information returned by the
        :py:meth:`~KyotoTycoon.status` API.

    .. py:method:: __getitem__(key_or_keydb)

        Item-lookup based on either ``key`` or a 2-tuple consisting of
        ``(key, db)``. Follows same semantics as :py:meth:`~KyotoTycoon.get`.

    .. py:method:: __setitem__(key_or_keydb, value_or_valueexpire)

        Item-setting based on either ``key`` or a 2-tuple consisting of
        ``(key, db)``. Value consists of either a ``value`` or a 2-tuple
        consisting of ``(value, expire_time)``. Follows same semantics
        as :py:meth:`~KyotoTycoon.set`.

    .. py:method:: __delitem__(key_or_keydb)

        Item-deletion based on either ``key`` or a 2-tuple consisting of
        ``(key, db)``. Follows same semantics as :py:meth:`~KyotoTycoon.remove`.

    .. py:method:: __contains__(key_or_keydb)

        Check if key exists. Accepts either ``key`` or a 2-tuple consisting of
        ``(key, db)``. Follows same semantics as :py:meth:`~KyotoTycoon.exists`.

    .. py:method:: __len__()

        :return: total number of keys in the default database.
        :rtype: int

    .. py:method:: update(__data=None, **kwargs)

        :param dict __data: optionally provide data as a dictionary.
        :param kwargs: provide data as keyword arguments.
        :return: number of keys that were set.

        Efficiently set or update multiple key/value pairs. Provided for
        compatibility with ``dict`` interface. For more control use the
        :py:meth:`~KyotoTycoon.set_bulk`.

    .. py:method:: pop(key, db=None, decode_value=True)

        Get and remove the data stored in a given key in a single operation.

        See :py:meth:`KyotoTycoon.seize`.

    .. py:method:: keys(db=None)

        :param int db: database index
        :return: all keys in database
        :rtype: generator

        .. warning::
            The :py:meth:`~KyotoCabinet.keys` method uses a cursor and can be
            very slow.

    .. py:method:: keys_nonlazy(db=None)

        :param int db: database index
        :return: all keys in database
        :rtype: list

        Non-lazy implementation of :py:meth:`~KyotoTycoon.keys`.
        Behind-the-scenes, calls :py:meth:`~KyotoTycoon.match_prefix` with an
        empty string as the prefix.

    .. py:method:: values(db=None)

        :param int db: database index
        :return: all values in database
        :rtype: generator

    .. py:method:: items(db=None)

        :param int db: database index
        :return: all key/value tuples in database
        :rtype: generator

    .. py:method:: __iter__()

        Iterating over the database yields an iterator over the keys of the
        database. Equivalent to :py:meth:`~KyotoTycoon.keys`.

    .. py:method:: touch(key, xt=None, db=None)

        :param str key: key to update.
        :param int xt: new expire time (or None).
        :param int db: database index.
        :return: old expire time or None if key not found.

        Run a lua function (touch) defined in scripts/kt.lua that allows one
        to update the TTL / expire time of a key.

        The old expire time is returned. If the key does not exist, then None
        is returned.

    .. py:method:: touch_bulk(keys, xt=None, db=None)

        :param list keys: keys to update.
        :param int xt: new expire time (or None).
        :param int db: database index.
        :return: a dict of key -> old expire time.

        Run a lua function (touch_bulk) defined in scripts/kt.lua that allows
        one to update the TTL / expire time of multiple keys.

        The return value is a dictionary of key -> old expire time. If the key
        does not exist, then the key is omitted from the return value.

    .. py:method:: touch_relative(key, n, db=None)

        :param str key: key to update.
        :param int n: seconds to increase expire-time.
        :param int db: database index.
        :return: new expire time or None if key not found.

        Run a lua function (touch_bulk_relative) defined in scripts/kt.lua that
        allows one to increment the TTL / expire time of a key.

        The new expire time is returned. If the key does not exist, then None
        is returned.

    .. py:method:: touch_bulk_relative(keys, n, db=None)

        :param list keys: keys to update.
        :param int n: seconds to increase expire-time.
        :param int db: database index.
        :return: a dict of key -> new expire time.

        Run a lua function (touch_bulk_relative) defined in scripts/kt.lua that
        allows one to update the TTL / expire time of multiple keys.

        The return value is a dictionary of key -> new expire time. If the key
        does not exist, then the key is omitted from the return value.

    .. py:method:: expire_time(key, db=None)

        :param str key: key to check.
        :param int db: database index
        :return: expire timestamp or None if key not found.

        Get the expire time by running a lua function (expire_time) defined in
        scripts/kt.lua.

    .. py:method:: expires(key, db=None)

        :param str key: key to check.
        :param int db: database index
        :return: expire ``datetime`` or None if key not found.

        Get the expire time as a ``datetime``.

    .. py:method:: error(db=None)

        :param int db: database index.
        :return: a 2-tuple of (code, message)

        Get the last error code and message.

        If the last command was successful, then (0, 'success') is returned.

    .. py:method:: Hash(key, encode_values=True, decode_values=True, db=None)

        :param str key: key to store the hash table.
        :param bool encode_values: serialize the hash values using the
            configured serializer.
        :param bool decode_values: de-serialize the hash values using the
            configured serializer.
        :param int db: database index.

        Create a :py:class:`Hash` container instance.

    .. py:method:: List(key, encode_values=True, decode_values=True, db=None)

        :param str key: key to store the list.
        :param bool encode_values: serialize the list items using the
            configured serializer.
        :param bool decode_values: de-serialize the list items using the
            configured serializer.
        :param int db: database index.

        Create a :py:class:`List` container instance.

    .. py:method:: Set(key, encode_values=True, decode_values=True, db=None)

        :param str key: key to store the set.
        :param bool encode_values: serialize the set keys using the
            configured serializer.
        :param bool decode_values: de-serialize the set keys using the
            configured serializer.
        :param int db: database index.

        Create a :py:class:`Set` container instance.

    .. py:method:: Queue(key, db=None)

        :param str key: key to use for the queue metadata.
        :param int db: database index.

        Create a :py:class:`Queue`, which provides efficient operations for
        implementing a priority queue.

    .. py:method:: Schedule(key, db=None)

        :param str key: key to use for the schedule metadata.
        :param int db: database index.

        Create a :py:class:`Schedule`, which provides efficient operations for
        implementing a sorted schedule.

    .. py:method:: cursor(db=None, cursor_id=None)

        :param int db: database index
        :param int cursor_id: cursor id (will be automatically created if None)
        :return: :py:class:`Cursor` object


.. py:class:: Cursor(protocol, cursor_id, db=None, decode_values=True, encode_values=True)

    :param KyotoTycoon protocol: client instance.
    :param int cursor_id: cursor unique identifier.
    :param int db: database index.
    :param bool decode_values: decode values using client serializer when
        reading from the cursor.
    :param bool encode_values: encode values using client serializer when
        writing to the cursor.

    Create a helper for working with the database using the cursor interface.

    .. py:method:: jump(key=None)

        :param str key: key to jump to or ``None``.
        :return: boolean indicating success.

        Jump to the given key. If not provided, will jump to the first key in
        the database.

    .. py:method:: jump_back(key=None)

        :param str key: key to jump backwards to or ``None``.
        :return: boolean indicating success.

        Jump backwards to the given key. If not provided, will jump to the last
        key in the database.

    .. py:method:: step()

        :return: boolean indicating success.

        Step to the next key. Returns ``False`` when past the last key of the
        database.

    .. py:method:: step_back()

        :return: boolean indicating success.

        Step to the previous key. Returns ``False`` when past the first key of
        the database.

    .. py:method:: key(step=False)

        :param bool step: step to next record after reading.
        :return: key of the currently-selected record.

    .. py:method:: value(step=False)

        :param bool step: step to next record after reading.
        :return: value of the currently-selected record.

    .. py:method:: get(step=False)

        :param bool step: step to next record after reading.
        :return: ``(key, value)`` of the currently-selected record.

    .. py:method:: set_value(value, step=False, expire_time=None)

        :param value: value to set
        :param bool step: step to next record after writing.
        :param int expire_time: optional expire time for record.
        :return: boolean indicating success.

        Set the value at the currently-selected record.

    .. py:method:: remove()

        :return: boolean indicating success.

        Remove the currently-selected record.

    .. py:method:: seize()

        :return: ``(key, value)`` of the currently-selected record.

        Get and remove the currently-selected record.

    .. py:method:: close()

        :return: boolean indicating success.

        Close the cursor.


.. py:class:: Queue(client, key, db=None)

    :param KyotoTycoon client: client instance.
    :param str key: key to store queue data.
    :param int db: database index.

    Priority queue implementation using lua functions (provided in
    the ``scripts/kt.lua`` module).

    .. py:method:: add(item, score=None)

        :param item: item to add to queue.
        :param int score: score (for priority support), higher values will be
            dequeued first. If not provided, defaults to ``0``.
        :return: id of newly-added item.

    .. py:method:: extend(items, score=None)

        :param list items: list of items to add to queue.
        :param int score: score (for priority support), higher values will be
            dequeued first. If not provided, defaults to ``0``.
        :return: number of items added to queue.

    .. py:method:: pop(n=1, min_score=None)

        :param int n: number of items to remove from queue.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: either a single item or a list of items (depending on ``n``).

        Pop one or more items from the head of the queue.

    .. py:method:: rpop(n=1, min_score=None)

        :param int n: number of items to remove from end of queue.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: either a single item or a list of items (depending on ``n``).

        Pop one or more items from the end of the queue.

    .. py:method:: bpop(timeout=None, min_score=None)

        :param int timeout: seconds to block before giving up.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: item from the head of the queue, or if no items are added
            before the timeout, ``None`` is returned.

        Pop an item from the queue, blocking if no items are available.

    .. py:method:: peek(n=1, min_score=None)

        :param int n: number of items to read from queue.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: either a single item or a list of items (depending on ``n``).

        Read (without removing) one or more items from the head of the queue.

    .. py:method:: rpeek(n=1, min_score=None)

        :param int n: number of items to read from end of queue.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: either a single item or a list of items (depending on ``n``).

        Read (without removing) one or more items from the end of the queue.

    .. py:method:: count()

        :return: number of items in the queue.

    .. py:method:: remove(data, n=None, min_score=None)

        :param data: value to remove from queue.
        :param int n: max occurrences to remove.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: number of items removed.

        Remove one or more items by value, starting from the head of the queue.

    .. py:method:: rremove(data, n=None, min_score=None)

        :param data: value to remove from end of queue.
        :param int n: max occurrences to remove.
        :param int min_score: minimum priority score. If not provided, all
            items will be considered regardless of score.
        :return: number of items removed.

        Remove one or more items by value, starting from the end of the queue.

    .. py:method:: transfer(dest, n=1)

        :param dest: destination queue key or :py:class:`Queue` instance.
        :param int n: number of items to transfer.
        :return: either the item that was transferred or the list of items
            that was transferred, depending on ``n``.

        Transfer items from the head of the queue to the tail of the
        destination queue. Priority scores are preserved. If the source queue
        is empty, then either ``None`` or an empty list will be returned
        (depending on whether ``n=1``).

    .. py:method:: set_priority(data, score, n=None)

        :param data: value to remove from end of queue.
        :param int score: new score for the item.
        :param int n: max occurrences to update.

        Update the priority of one or more items in the queue, by value.

    .. py:method:: clear()

        :return: number of items in queue when cleared.

        Remove all items from queue.


.. py:class:: Schedule(client, key, db=None)

    :param KyotoTycoon client: client instance.
    :param str key: key to store schedule data.
    :param int db: database index.

    Prioritized schedule implementation using lua functions (provided in
    the ``scripts/kt.lua`` module).

    .. py:method:: add(item, score=0)

        :param item: add an item to the schedule.
        :param int score: score (arrival time) of item.

        Add an item to the schedule, with a given score / arrival time.

    .. py:method:: read(score=None, n=None)

        :param int score: score threshold or arrival time
        :param int n: maximum number of items to read.
        :return: a list of items

        Destructively read up-to ``n`` items from the schedule, whose item
        score is below the given ``score``.

    .. py:method:: clear()

        Clear the schedule, removing all items.

    .. py:method:: count()

        :return: number of items in the schedule.

        Return the number of items in the schedule.

    .. py:method:: items(n=None)

        :param int n: limit the number of items to read.
        :return: a list of up-to ``n`` items from the schedule.

        Non-destructively read up-to ``n`` items from the schedule, in order of
        score.


Container types
---------------

Simple container types that emulate Python or Redis types, and rely on Kyoto
Tycoon's lua serialization helpers. Behind-the scenes, these types are using
lua functions to read the entire value into a Lua table and write it back.
Because the full data must be deserialized for reading, and re-serialized for
writing, all operations are O(n).

These container types support transparent serialization using the configured
serializer (``KT_PICKLE``, ``KT_MSGPACK``, etc).

.. py:class:: Hash(kt, key, encode_values=True, decode_values=True, db=None)

    :param KyotoTycoon kt: client
    :param str key: key to store hash data
    :param bool encode_values: values should be serialized using the configured
        serializer (e.g., KT_PICKLE, KT_MSGPACK, etc).
    :param bool decode_values: values should be deserialized using the
        configured serializer.
    :param int db: database index to store hash. If not specified, will use the
        default db configured for the kt client.

    .. py:method:: set_bulk(__data=None, **kwargs)

        :param dict __data: provide data as a dictionary.
        :param kwargs: or provide data keyword arguments.
        :return: number of keys that were set.

        Update the data stored in the hash.

    .. py:method:: get_bulk(keys)

        :param keys: an iterable of keys to fetch.
        :return: a dictionary of key/value pairs. If a requested key is not
            found, it is not included in the returned data.

    .. py:method:: remove_bulk(keys)

        :param keys: an iterable of keys to remove.
        :return: number of key/value pairs that were removed.

    .. py:method:: get_all()

        :return: dictionary of all data stored in the hash

        A more efficient implementation utilizes the Python implementation of
        the lua serializers. Use :py:meth:`Hash.get_raw`.

    .. py:method:: set(key, value)

        :param str key: key to store
        :param value: data

        Set a single key/value pair in the hash. Returns number of records
        written (1).

    .. py:method:: setnx(key, value)

        :param str key: key to store
        :param value: data
        :return: 1 on success, 0 if key already exists.

        Set a single key/value pair in the hash only if the key does not
        already exist.

    .. py:method:: get(key)

        :param str key: key to fetch
        :return: value, if key exists, or ``None``.

    .. py:method:: remove(key)

        :param str key: key to remove
        :return: number of keys removed, 1 on success, 0 if key not found.

    .. py:method:: length()

        :return: total number of keys in the hash.

    .. py:method:: contains(key)

        :param str key: key to check
        :return: boolean indicating whether the given key exists.

    .. py:method:: unpack(prefix=None)

        :param str prefix: prefix for unpacked-keys
        :return: number of keys that were written

        Unpack the key/value pairs in the hash into top-level key/value pairs
        in the database, optionally prefixing the unpacked keys with the given
        prefix.

    .. py:method:: pack(start=None, stop=None, count=None)

        :param str start: start key, or will be first key in the database
        :param str stop: stop key, or will be last key in the database
        :param int count: limit number of keys to pack
        :return: number of keys that were packed

        Pack a range of key/value pairs in the database into a hash.

    .. py:method:: pack_keys(key)

        :param str key: destination key for :py:class:`List` of keys.
        :return: number of keys that were written to the list

        Pack the keys of the hash into a :py:class:`List` at the given key.

    .. py:method:: pack_values(key)

        :param str key: destination key for :py:class:`List` of values.
        :return: number of values that were written to the list

        Pack the values of the hash into a :py:class:`List` at the given key.

    .. py:method:: __len__()

        See :py:meth:`~Hash.length`.

    .. py:method:: __contains__()

        See :py:meth:`~Hash.contains`.

    .. py:method:: __getitem__()

        See :py:meth:`~Hash.get`.

    .. py:method:: __setitem__()

        See :py:meth:`~Hash.set`.

    .. py:method:: __detitem__()

        See :py:meth:`~Hash.remove`.

    .. py:method:: update(__data=None, **kwargs)

        See :py:meth:`~Hash.set_bulk`.

    .. py:method:: get_raw()

        :return: dictionary of all data stored in hash, or ``None`` if empty.

        Utilize a more-efficient implementation for fetching all data stored in
        the hash. Rather than going through Lua, we read the raw value of the
        serialized hash, then deserialize it using an equivalent format to KT's
        internal ``mapload`` format.

    .. py:method:: set_raw(d)

        :param dict d: dictionary of all data to store in hash.

        Utilize a more-efficient implementation for setting the data stored in
        the hash. Rather than going through Lua, we write the raw value of the
        serialized hash, using an equivalent format to KT's internal
        ``mapdump`` format.


.. py:class:: List(kt, key, encode_values=True, decode_values=True, db=None)

    :param KyotoTycoon kt: client
    :param str key: key to store list data
    :param bool encode_values: values should be serialized using the configured
        serializer (e.g., KT_PICKLE, KT_MSGPACK, etc).
    :param bool decode_values: values should be deserialized using the
        configured serializer.
    :param int db: database index to store list. If not specified, will use the
        default db configured for the kt client.

    .. py:method:: appendleft(value)

        :param value: value to append to left-side (head) of list.
        :return: length of list after operation.

    .. py:method:: appendright(value)

        :param value: value to append to right-side (tail) of list.
        :return: length of list after operation.

    .. py:method:: append(value)

        Alias for :py:meth:`~List.appendright`.

    .. py:method:: extend(values)

        :param values: an iterable of values to add to the tail of the list.
        :return: length of list after operation.

    .. py:method:: get_range(start=None, stop=None)

        :param int start: start index (0 for first element)
        :param int stop: stop index. Supports negative values.
        :return: a list of items corresponding to the given range.

        Slicing operation equivalent to Python's list slice behavior. If the
        start or stop indices are out-of-bounds, the return value will be an
        empty list.

    .. py:method:: index(index)

        :param int index: item index to fetch. Supports negative values.
        :return: the value at the given index

        Indexing operation equivalent to Python's list item lookup. If the
        index is out-of-bounds, an :py:class:`IndexError` will be raised.

    .. py:method:: insert(index, value)

        :param int index: index at which new value should be inserted. Supports
            negative values.
        :param value: value to insert
        :return: length of list after operation

        Insert an item into the list at the given index. If the index is
        out-of-bounds, an :py:class:`IndexError` will be raised.

    .. py:method:: remove(index)

        :param int index: item index to remove. Supports negative values.
        :return: the value at the given index

        Remove and return an item from the list by index. If the index is
        out-of-bounds, an :py:class:`IndexError` will be raised.

    .. py:method:: remove_range(start=None, stop=None)

        :param int start: start index to remove. Supports negative values.
        :param int stop: stop index of range to remove. Supports negative
            values.
        :return: length of list after operation

        Remove a range of values by index.

    .. py:method:: popleft()

        :return: item at head of list or ``None`` if list is empty.

    .. py:method:: popright()

        :return: item at tail of list or ``None`` if list is empty.

    .. py:method:: pop(index=None)

        :param int index: index to pop (optional), or ``None`` to remove the
            item at the tail of the list.
        :return: item removed or ``None`` if list is empty or the index is
            out-of-bounds.

    .. py:method:: lpoprpush(dest=None)

        :param dest: destination key (or :py:class:`List` object). If
            unspecified, the destination will be the current list and the
            operation is equivalent to a rotation.
        :return: item that was moved, if source is not empty. If source list is
            empty, an :py:class:`IndexError` is raised.

        Pop the item at the head of the current list and push it to the tail of
        the dest list.

    .. py:method:: rpoplpush(dest=None)

        :param dest: destination key (or :py:class:`List` object). If
            unspecified, the destination will be the current list and the
            operation is equivalent to a rotation.
        :return: item that was moved, if source is not empty. If source list is
            empty, an :py:class:`IndexError` is raised.

        Pop the item at the tail of the current list and push it to the head of
        the dest list.

    .. py:method:: length()

        :return: length of the list.

    .. py:method:: set(index, value)

        :param int index: index to set. Supports negative values.
        :param value: value to set at given index

        Set the value at the given index. If the index is out-of-bounds, an
        :py:class:`IndexError` will be raised.

    .. py:method:: find(value)

        :param value: value to search for
        :return: index of first occurrance of value starting from head of list.

    .. py:method:: rfind(value)

        :param value: value to search for
        :return: index of first occurrance of value starting from tail of list.

    .. py:method:: unpack(start=None, stop=None, prefix=None, fmt=None)

        :param int start: start index of range to unpack
        :param int stop: stop index of range to unpack
        :param str prefix: prefix for output values
        :param str fmt: lua format-string for index, e.g. `'%08d'`.

        Unpack the items in the list into top-level keys in the database. The
        key will begin with the provided prefix, and optionally accepts a
        format-string for formatting the index.

    .. py:method:: pack(start=None, stop=None, count=None)

        :param str start: start key, or will be first key in the database
        :param str stop: stop key, or will be last key in the database
        :param int count: limit number of keys to pack
        :return: number of keys that were packed

        Pack the values for a range of keys in the database into a list.

    .. py:method:: __len__()

        See :py:meth:`~List.length`.

    .. py:method:: __contains__()

        See :py:meth:`~List.find`.

    .. py:method:: __getitem__()

        Supports item indexes or slices. See :py:meth:`~List.index` and
        :py:meth:`~List.get_range`.

    .. py:method:: __setitem__()

        See :py:meth:`~List.set`.

    .. py:method:: __detitem__()

        See :py:meth:`~List.remove`.

    .. py:method:: get_raw()

        :return: list of all data stored in list, or ``None`` if empty.

        Utilize a more-efficient implementation for fetching all data stored in
        the list. Rather than going through Lua, we read the raw value of the
        serialized list, then deserialize it using an equivalent format to KT's
        internal ``arrayload`` format.

    .. py:method:: set_raw(l)

        :param list l: list of all data to store in list.

        Utilize a more-efficient implementation for setting the data stored in
        the list. Rather than going through Lua, we write the raw value of the
        serialized list, using an equivalent format to KT's internal
        ``arraydump`` format.


Embedded Servers
----------------

.. py:class:: EmbeddedServer(server='ktserver', host='127.0.0.1', port=None, database='*', serializer=None, server_args=None, quiet=False)

    :param str server: path to ktserver executable.
    :param str host: host to bind server on.
    :param int port: port to use (optional).
    :param str database: database filename, default is in-memory hash table.
    :param serializer: serializer to use, e.g. ``KT_BINARY`` or ``KT_MSGPACK``.
    :param list server_args: additional command-line arguments for server
    :param bool quiet: minimal logging and output.

    Create a manager for running an embedded (sub-process) Kyoto Tycoon server.
    If the port is not specified, a random high port will be used.

    Example:

    .. code-block:: pycon

        >>> from kt import EmbeddedServer
        >>> server = EmbeddedServer()
        >>> server.run()
        True
        >>> client = server.client
        >>> client.set('k1', 'v1')
        1
        >>> client.get('k1')
        'v1'
        >>> server.stop()
        True

    .. py:method:: run()

        :return: boolean indicating if server successfully started

        Run ``ktserver`` in a sub-process.

    .. py:method:: stop()

        :return: boolean indicating if server was stopped

        Stop the running embedded server.

    .. py:attribute:: client

        :py:class:`KyotoTycoon` client bound to the embedded server.
