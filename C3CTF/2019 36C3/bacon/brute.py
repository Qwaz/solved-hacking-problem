#!/usr/bin/env python3
import itertools
import sys

MASK = 0xffffff


def forward(key, blk):
    assert tuple(map(len, (key, blk))) == (9, 6)
    def S(j, v): return (v << j | (v & MASK) >> 24-j) & MASK
    ws = blk[:3], blk[3:], key[:3], key[3:6], key[6:]
    x, y, l1, l0, k0 = (int.from_bytes(w, 'big') for w in ws)
    l, k = [l0, l1], [k0]
    for i in range(21):
        l.append((S(16, l[i]) + k[i] ^ i) & MASK)
        k.append(S(3, k[i]) ^ l[-1])
    for i in range(22):
        x = (S(16, x) + y ^ k[i]) & MASK
        y = (S(3, y) ^ x) & MASK
    return b''.join(z.to_bytes(3, 'big') for z in (x, y))


def backward(key, cipher):
    assert tuple(map(len, (key, cipher))) == (9, 6)
    def S(j, v): return (v << j | (v & MASK) >> 24-j) & MASK
    ws = cipher[:3], cipher[3:], key[:3], key[3:6], key[6:]
    x, y, l1, l0, k0 = (int.from_bytes(w, 'big') for w in ws)
    l, k = [l0, l1], [k0]
    for i in range(21):
        l.append((S(16, l[i]) + k[i] ^ i) & MASK)
        k.append(S(3, k[i]) ^ l[-1])
    for i in range(21, -1, -1):
        y = S(21, y ^ x)
        x = S(8, (x ^ k[i]) - y)
    x, y = (z & 0xffffff for z in (x, y))
    return b''.join(z.to_bytes(3, 'big') for z in (x, y))


# did I implement this correctly?
assert forward(*map(bytes.fromhex, ('1211100a0908020100',
                                    '20796c6c6172'))) == b'\xc0\x49\xa5\x38\x5a\xdc'


def H(m):
    s = bytes(6)
    v = m + bytes(-len(m) % 9) + len(m).to_bytes(9, 'big')
    for i in range(0, len(v), 9):
        s = forward(v[i:i+9], s)
    return s


if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} <hex>")
    exit(1)

target = bytes.fromhex(sys.argv[1])


key = (18).to_bytes(9, 'big')

start = bytes(6)
end = backward(key, target)

assert(forward(key, end) == target)

forward_dict = {}
backward_dict = {}

all_bytes = [i.to_bytes(1, 'big') for i in range(256)]
for k in itertools.product(all_bytes, repeat=9):
    key = b''.join(k)
    f = forward(key, start)
    forward_dict[f] = key
    if f in backward_dict:
        ans = key + backward_dict[f]
        break
    b = backward(key, end)
    backward_dict[b] = key
    if b in forward_dict:
        ans = forward_dict[b] + key
        break

print(ans.hex())
assert H(ans) == target
