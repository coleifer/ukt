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

    .. py:method:: set_bulk_raw(data, no_reply=False, encode_values=True)

        :param list data: a list of 4-tuples: ``(db, key, value, expire time)``
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

    .. py:method:: remove_bulk(keys, db=None, no_reply=False)

        :param list keys: list of keys to remove
        :param int db: database index
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of keys that were removed

    .. py:method:: remove_bulk_raw(db_key_list, no_reply=False)

        :param db_key_list: a list of 2-tuples to retrieve: ``(db index, key)``
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of keys that were removed

        Like :py:meth:`~KyotoTycoon.remove_bulk`, but allows keys to be removed
        from multiple databases in a single call.

    .. py:method:: remove(key, db=None, no_reply=False)

        :param str key: key to remove
        :param int db: database index
        :param bool no_reply: execute the operation without a server
            acknowledgment.
        :return: number of rows removed

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

    .. py:method:: exists(key, db=None)

        :param str key: key to test.
        :param int db: database index.
        :return: boolean indicating if key exists.

        Return whether or not the given key exists in the database.

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

    .. py:method:: seize(key, db=None, decode_value=True)

        :param str key: key to remove.
        :param int db: database index.
        :param bool decode_value: deserialize the value using the configured
            serialization method.
        :return: value stored at given key or ``None`` if key does not exist.

        Perform atomic get-and-remove the value stored in a given key. This
        method is also available as :py:meth:`KyotoTycoon.pop` if that's easier
        to remember.

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

    .. py:method:: length(key, db=None)

        :param str key: key.
        :param int db: database index.
        :return: length of the value in bytes, or ``None`` if not found.

        Return the length of the raw value stored at the given key. If the key
        does not exist, returns ``None``.

    .. py:method:: clear(db=None)

        :param int db: database index
        :return: boolean indicating success

        Remove all keys from the database.

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

    .. py:method:: report()

        :return: status fields and values
        :rtype: dict

        Obtain report on overall status of server, including all databases.

    .. py:method:: status(db=None)

        :param int db: database index
        :return: status fields and values
        :rtype: dict

        Obtain status information from the server about the selected database.

    .. py:method:: synchronize(hard=False, command=None, db=None)

        :param bool hard: perform a "hard" synchronization.
        :param str command: command to execute after synchronization.
        :param int db: database index.
        :return: boolean indicating success.

        Synchronize the database, optionally executing the given command upon
        success. This can be used to create hot backups, for example.

    .. py:method:: vacuum(step=0, db=None)

        :param int step: number of steps, default is 0
        :param int db: database index
        :return: boolean indicating success

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

    .. py:method:: cursor(db=None, cursor_id=None)

        :param int db: database index
        :param int cursor_id: cursor id (will be automatically created if None)
        :return: :py:class:`Cursor` object

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

    .. py:method:: serialize_dict(d)

        :param dict d: arbitrary data.
        :return: serialized data.

        Serialize a ``dict`` as a sequence of bytes compatible with KT's
        built-in lua ``mapdump`` function.

    .. py:method:: deserialize_dict(data, decode_values=True)

        :param bytes data: serialized data.
        :param bool decode_values: decode values to unicode strings.
        :return: data ``dict``.

        Deserialize a a sequence of bytes into a dictionary, optionally
        decoding the values as unicode strings. Compatible with KT's built-in
        lua ``mapload`` function.

    .. py:method:: serialize_list(l)

        :param list l: arbitrary data.
        :return: serialized data.

        Serialize a ``list`` as a sequence of bytes compatible with KT's
        built-in lua ``arraydump`` function.

    .. py:method:: deserialize_list(data, decode_values=True)

        :param bytes data: serialized data.
        :param bool decode_values: decode values to unicode strings.
        :return: data ``list``.

        Deserialize a a sequence of bytes into a list, optionally decoding the
        values as unicode strings. Compatible with KT's built-in lua
        ``arrayload`` function.


.. py:class:: Cursor(protocol, cursor_id, db=None)

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

    .. py:method:: seize(step=False)

        :param bool step: step to next record after writing.
        :return: ``(key, value)`` of the currently-selected record.

        Get and remove the currently-selected record.

    .. py:method:: close()

        :return: boolean indicating success.

        Close the cursor.


.. py:class:: Queue(client, key, db=None)

    :param KyotoTycoon client: client instance.
    :param str key: key to store queue data.
    :param int db: database index.

    Queue implementation using lua functions (provided in ``scripts/kt.lua``).

    .. py:method:: add(item)

        :param item: item to add to queue.
        :return: id of newly-added item.

    .. py:method:: extend(items)

        :param list items: list of items to add to queue.
        :return: number of items added to queue.

    .. py:method:: pop(n=1)

        :param int n: number of items to remove from queue.
        :return: either a single item or a list of items (depending on ``n``).

    .. py:method:: rpop(n=1)

        :param int n: number of items to remove from end of queue.
        :return: either a single item or a list of items (depending on ``n``).

    .. py:method:: peek(n=1)

        :param int n: number of items to read from queue.
        :return: either a single item or a list of items (depending on ``n``).

    .. py:method:: rpeek(n=1)

        :param int n: number of items to read from end of queue.
        :return: either a single item or a list of items (depending on ``n``).

    .. py:method:: count()

        :return: number of items in the queue.

    .. py:method:: remove(data, n=None)

        :param data: value to remove from queue.
        :param int n: max occurrences to remove.
        :return: number of items removed.

    .. py:method:: rremove(data, n=None)

        :param data: value to remove from end of queue.
        :param int n: max occurrences to remove.
        :return: number of items removed.

    .. py:method:: clear()

        :return: number of items in queue when cleared.

        Remove all items from queue.


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
