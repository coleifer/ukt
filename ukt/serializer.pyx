# cython: language_level=3
cimport cython
from cpython.bytes cimport PyBytes_AsStringAndSize
from cpython.bytes cimport PyBytes_Check
from cpython.unicode cimport PyUnicode_AsUTF8String
from cpython.unicode cimport PyUnicode_Check
from cpython.unicode cimport PyUnicode_DecodeUTF8
from cpython.version cimport PY_MAJOR_VERSION
from libc.stdint cimport uint32_t
from libc.stdint cimport uint64_t
from libc.stdlib cimport free
from libc.stdlib cimport malloc
from libc.string cimport memcpy

import io


cdef bint IS_PY3K = PY_MAJOR_VERSION == 3

cdef inline bytes _encode(obj):
    cdef bytes result
    if PyUnicode_Check(obj):
        result = PyUnicode_AsUTF8String(obj)
    elif PyBytes_Check(obj):
        result = <bytes>obj
    elif obj is None:
        return None
    elif IS_PY3K:
        result = PyUnicode_AsUTF8String(str(obj))
    else:
        result = bytes(obj)
    return result

cdef inline unicode _decode(obj):
    cdef:
        unicode result
        char *buf
        Py_ssize_t n

    if PyBytes_Check(obj):
        PyBytes_AsStringAndSize(<bytes>obj, &buf, &n)
        result = PyUnicode_DecodeUTF8(buf, n, NULL)
    elif PyUnicode_Check(obj):
        result = <unicode>obj
    elif obj is None:
        return None
    else:
        result = unicode(obj)
    return result

def encode(obj):
    return _encode(obj)

def decode(obj):
    return _decode(obj)


# Serialization method compatible with KyotoTycoon's lua "mapdump" function.
def _serialize_dict(dict d):
    cdef:
        bytes bkey, bnum, bvalue
        char *kbuf
        char *vbuf
        int knbytes, vnbytes
        Py_ssize_t kbuflen, vbuflen
        unsigned char knumbuf[8]
        unsigned char vnumbuf[8]

    data = io.BytesIO()

    for key in d:
        bkey = _encode(key)
        bvalue = _encode(d[key])
        PyBytes_AsStringAndSize(bkey, &kbuf, &kbuflen)
        PyBytes_AsStringAndSize(bvalue, &vbuf, &vbuflen)

        knbytes = _writevarnum(knumbuf, <uint64_t>kbuflen)
        vnbytes = _writevarnum(vnumbuf, <uint64_t>vbuflen)
        data.write(knumbuf[:knbytes])
        data.write(vnumbuf[:vnbytes])
        data.write(bkey)
        data.write(bvalue)

    return data.getvalue()


# Serialization method compatible with KyotoTycoon's lua "mapload" function.
def _deserialize_dict(raw_data, deserialize=True):
    cdef:
        Py_ssize_t buflen
        bytes data = encode(raw_data)
        bytes bkey, bval
        char *buf
        char *kbuf = <char *>malloc(128 * sizeof(char))
        char *vbuf = <char *>malloc(1024 * sizeof(char))
        dict accum = {}
        size_t kitemsize = 128
        size_t vitemsize = 1024
        size_t kstep, vstep
        uint64_t knum, vnum

    # Get reference to underlying pointer and length of data.
    PyBytes_AsStringAndSize(data, &buf, &buflen)

    while buflen > 0:
        # Read a variable-sized integer from the data buffer. The number of
        # bytes used to encode the number is returned as "kstep", and the
        # number itself is stored in "knum".
        kstep = _readvarnum(<unsigned char *>buf, buflen, &knum)

        if buflen < kstep + knum:
            free(kbuf); free(vbuf)
            raise ValueError('corrupt key, refusing to process')

        # Move the data pointer forward to the start of the value size.
        buf += kstep
        buflen -= kstep

        vstep = _readvarnum(<unsigned char *>buf, buflen, &vnum)

        if buflen < vstep + vnum:
            free(kbuf); free(vbuf)
            raise ValueError('corrupt value, refusing to process')

        # Move to start of key data.
        buf += vstep
        buflen -= vstep

        # Can we reuse our item buffer?
        if knum > kitemsize:
            free(kbuf)
            kbuf = <char *>malloc(knum * sizeof(unsigned char))

        memcpy(kbuf, buf, knum)
        bkey = kbuf[:knum]

        # Move to start of value.
        buf += knum
        buflen -= knum

        if vnum > vitemsize:
            free(vbuf)
            vbuf = <char *>malloc(vnum * sizeof(unsigned char))

        memcpy(vbuf, buf, vnum)
        bval = vbuf[:vnum]

        # Move to end of value.
        buf += vnum
        buflen -= vnum

        if deserialize:
            accum[_decode(bkey)] = _decode(bval)
        else:
            accum[_decode(bkey)] = bval

    if kbuf:
        free(kbuf)
    if vbuf:
        free(vbuf)

    return accum


# Serialization method compatible with KyotoTycoon's lua "arraydump" function.
def _serialize_list(l):
    cdef:
        bytes bnum, bvalue
        char *buf
        int i
        int nbytes
        Py_ssize_t buflen
        unsigned char numbuf[8]

    data = io.BytesIO()

    for i in range(len(l)):
        bvalue = _encode(l[i])
        PyBytes_AsStringAndSize(bvalue, &buf, &buflen)
        nbytes = _writevarnum(numbuf, <uint64_t>buflen)
        data.write(numbuf[:nbytes])
        data.write(bvalue)

    return data.getvalue()


# Serialization method compatible with KyotoTycoon's lua "arrayload" function.
def _deserialize_list(raw_data, deserialize=True):
    cdef:
        Py_ssize_t buflen
        bytes data = encode(raw_data)
        bytes bitem
        char *buf
        char *item = <char *>malloc(1024 * sizeof(char))
        list accum = []
        size_t itemsize = 1024
        size_t step
        uint64_t num

    # Get reference to underlying pointer and length of data.
    PyBytes_AsStringAndSize(data, &buf, &buflen)

    while buflen > 0:
        # Read a variable-sized integer from the data buffer. The number of
        # bytes used to encode the number is returned as "step", and the number
        # itself is stored in "num".
        step = _readvarnum(<unsigned char *>buf, buflen, &num)

        if buflen < step + num:
            free(item)
            raise ValueError('corrupt array item, refusing to process')

        # Move the data pointer forward to the start of the data.
        buf += step
        buflen -= step

        # Can we reuse our item buffer?
        if num > itemsize:
            free(item)
            item = <char *>malloc(num * sizeof(unsigned char))

        memcpy(item, buf, num)
        bitem = item[:num]
        if deserialize:
            accum.append(_decode(bitem))
        else:
            accum.append(bitem)
        buf += num
        buflen -= num

    if item:
        free(item)

    return accum


cdef inline int _writevarnum(unsigned char *buf, uint64_t num):
    if num < (1 << 7):
        buf[0] = <unsigned char>num
        return 1
    elif num < (1 << 14):
        buf[0] = <unsigned char>((num >> 7) | 0x80)
        buf[1] = <unsigned char>(num & 0x7f)
        return 2
    elif num < (1 << 21):
        buf[0] = <unsigned char>((num >> 14) | 0x80)
        buf[1] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(num & 0x7f)
        return 3
    elif num < (1 << 28):
        buf[0] = <unsigned char>((num >> 21) | 0x80)
        buf[1] = <unsigned char>(((num >> 14) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[3] = <unsigned char>(num & 0x7f)
        return 4
    elif num < (1 << 35):
        buf[0] = <unsigned char>((num >> 28) | 0x80)
        buf[1] = <unsigned char>(((num >> 21) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(((num >> 14) & 0x7f) | 0x80)
        buf[3] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[4] = <unsigned char>(num & 0x7f)
        return 5
    elif num < (1 << 42):
        buf[0] = <unsigned char>((num >> 35) | 0x80)
        buf[1] = <unsigned char>(((num >> 28) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(((num >> 21) & 0x7f) | 0x80)
        buf[3] = <unsigned char>(((num >> 14) & 0x7f) | 0x80)
        buf[4] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[5] = <unsigned char>(num & 0x7f)
        return 6
    elif num < (1 << 49):
        buf[0] = <unsigned char>((num >> 42) | 0x80)
        buf[1] = <unsigned char>(((num >> 35) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(((num >> 28) & 0x7f) | 0x80)
        buf[3] = <unsigned char>(((num >> 21) & 0x7f) | 0x80)
        buf[4] = <unsigned char>(((num >> 14) & 0x7f) | 0x80)
        buf[5] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[6] = <unsigned char>(num & 0x7f)
        return 7
    elif num < (1 << 56):
        buf[0] = <unsigned char>((num >> 49) | 0x80)
        buf[1] = <unsigned char>(((num >> 42) & 0x7f) | 0x80)
        buf[2] = <unsigned char>(((num >> 35) & 0x7f) | 0x80)
        buf[3] = <unsigned char>(((num >> 28) & 0x7f) | 0x80)
        buf[4] = <unsigned char>(((num >> 21) & 0x7f) | 0x80)
        buf[5] = <unsigned char>(((num >> 14) & 0x7f) | 0x80)
        buf[6] = <unsigned char>(((num >> 7) & 0x7f) | 0x80)
        buf[7] = <unsigned char>(num & 0x7f)
        return 8
    return 0


cdef inline size_t _readvarnum(unsigned char *buf, size_t size, uint64_t *np):
    cdef:
        unsigned char *rp = buf
        unsigned char *ep = rp + size
        uint64_t num = 0
        uint32_t c

    while rp < ep:
        if rp >= ep:
            np[0] = 0
            return 0
        c = rp[0]
        num = (num << 7) + (c & 0x7f)
        rp += 1
        if c < 0x80:
            break
    np[0] = num
    return rp - <unsigned char *>buf
