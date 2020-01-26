#!/usr/bin/env python3
import os, signal

def Speck(key, blk):
    assert tuple(map(len, (key, blk))) == (9,6)
    S = lambda j,v: (v << j | (v&0xffffff) >> 24-j)
    ws = blk[:3],blk[3:], key[:3],key[3:6],key[6:]
    x,y, l1,l0,k0 = (int.from_bytes(w,'big') for w in ws)
    l, k = [l0,l1], [k0]
    for i in range(21):
        l.append(S(16,l[i]) + k[i] ^ i)
        k.append(S( 3,k[i])        ^ l[-1])
    for i in range(22):
        x = S(16,x) + y ^ k[i]
        y = S( 3,y)     ^ x
    x,y = (z&0xffffff for z in (x,y))
    return b''.join(z.to_bytes(3,'big') for z in (x,y))

# did I implement this correctly?
assert Speck(*map(bytes.fromhex, ('1211100a0908020100', '20796c6c6172'))) == b'\xc0\x49\xa5\x38\x5a\xdc'

def H(m):
    s = bytes(6)
    v = m + bytes(-len(m) % 9) + len(m).to_bytes(9,'big')
    for i in range(0,len(v),9):
        s = Speck(v[i:i+9], s)
    return s


signal.alarm(100)

h = os.urandom(6)
print(h.hex())

s = bytes.fromhex(input())
if H(s) == h:
    print('The flag is: {}'.format(open('flag.txt').read().strip()))
else:
    print('Nope.')

