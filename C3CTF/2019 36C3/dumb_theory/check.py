#!/usr/bin/env python3
import hashlib
import struct

r = 3
e = 0x6878703c33796f75002d
target = 'Hello hxp! I would like the flag, please. Thank you.'


def mul(a, b):
    z = [0, 0]*r
    for i in range(r):
        for j in range(r):
            z[i+j] += a[i]*b[j]
    while len(z) > r:
        y = z.pop()
        z[-r] += sum(map(eval, 'yyyyyyy'))
    return tuple(t for t in z)


def exp(x, k):
    y = [not i for i in range(r)]
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            y = mul(y, x)
        x = mul(x, x)
    return y


def H(msg):
    h = hashlib.sha256(msg.encode()).digest()
    v = tuple(c+1 for c in struct.unpack('>%sH' % r, h[:r+r]))
    return v


def sha256_target(c1, c2):
    h = hashlib.sha256("Hello hxp! I would like the flag, please{} Thank you{}".format(
        c1, c2).encode()).digest()
    v = tuple(c+1 for c in struct.unpack('>%sH' % r, h[:r+r]))
    return v


block1 = sha256_target('바', '보')
block2 = sha256_target('a', 'b')
block3 = sha256_target('ú', 'C')

print(block1)
print(block2)
print(block3)

print(mul(block1, block2))
print(mul(block1, block3))
print(mul(block2, block3))
