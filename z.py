from ukt import *
from ukt.script import *


kt = KyotoTycoon(serializer=KT_MSGPACK)
kt.clear()

h1 = Hash(kt, 'hash1')
h2 = Hash(kt, 'hash2')

n = h1.mset({'k1': 'v1', 'k2': ['i0', 'i1', 'i2'], 'k3': {'x1': 'y1', 'x2': 'y2'}})
assert n == 3

res = h1.mget(['k1', 'k2', 'k3', 'k4'])
print(res)

assert h1['k2'] == ['i0', 'i1', 'i2']
h1['k4'] = ['foo', 'baz']

assert h1.setnx('k1', 'v1-x') == 0
assert h1.set('k1', 'v1-z') == 1
assert h1.length() == 4
assert h1.delete('k2') == 1
assert h1.delete('k2') == 0
assert h1.length() == 3
assert h1.contains('k1') == 1
assert h1.contains('k2') == 0

print(h1.get_all())

h2.set('k2', 'v2')
h2.set('k3', 'v3')
del h2['k2']
print(h2.get_all())

####

s = Set(kt, 's1')
assert s.add('k1') == 1
assert s.madd(('k2', 'k3', 'k4', 'k1')) == 3
assert s.madd(('k2', 'k3', 'k4', 'k1')) == 0
assert s.count() == 4
assert s.contains('k1')
assert s.contains('kx') == 0
assert s.members() == {'k1', 'k2', 'k3', 'k4'}
v = s.pop()
assert v in {'k1', 'k2', 'k3', 'k4'}
s.add('k1', 'k2', 'k3', 'k4')
assert s.delete('k1') == 1
assert s.delete('k1') == 0

####

l = List(kt, 'l1')
l.append('i2')
l.appendleft('i1')
l.appendright('i4')
l.insert(2, 'i3')
print(l.get_range())
l[2] = 'i3-x'
assert l[:] == ['i1', 'i2', 'i3-x', 'i4']
