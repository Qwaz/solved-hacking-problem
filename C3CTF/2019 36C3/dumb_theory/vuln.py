#!/usr/bin/env python3
import random, struct, re, sys, hashlib, gmpy2

num_problems_i_got = 99  # but a forgery ain't one
r = 3
e = 0x6878703c33796f75002d
target = 'Hello hxp! I would like the flag, please. Thank you.'

while True:
    p = int(gmpy2.next_prime(random.randrange(1 << 444)))
    q = int(gmpy2.next_prime(random.randrange(1 << 444)))
    u = (p**r-1) * (q**r-1)
    g,d,_ = map(int, gmpy2.gcdext(e,u))
    if g == 1: break

d %= u
n = p*q
print(n)

################################################################

class No(Exception): pass

def mul(a, b):
    z = [0,0]*r
    for i in range(r):
        for j in range(r):
            z[i+j] += a[i]*b[j]
    while len(z) > r:
        y = z.pop()
        z[-r] += sum(map(eval, 'yyyyyyy'))
    return tuple(t%n for t in z)

def exp(x, k):
    y = [not i for i in range(r)]
    for i in range(k.bit_length()):
        if (k>>i)&1: y = mul(y,x)
        x = mul(x,x)
    return y

def H(msg):
    h = hashlib.sha256(msg.encode()).digest()
    v = tuple(c+1 for c in struct.unpack(f'>{r}H', h[:r+r]))
    if v in H.seen: raise No()  # NO COLLISION, OBSTRUCTION!
    H.seen.add(v)
    return v
H.seen = set()

################################################################

flag = open('flag.txt').read().strip()

for it in range(num_problems_i_got):

    print(f'{it:03}> ', end=''); sys.stdout.flush()
    try:
        data = input()
    except EOFError:
        exit()

    if 'flag' not in data:
        print('|'.join(map(str, exp(H(data), d))))
        continue

    try:

        m = re.match(f'({target}) Signature: ([0-9|]+)', data)
        if m is None: raise No()
        if m.groups()[1].count('|') != r-1: raise No()

        msg, sig = m.groups()[0], tuple(map(int, m.groups()[1].split('|')))
        if exp(sig,e) == H(msg):
            print(f'Absolutely no problem at all Sir! Here you go: {flag}')
        else:
            print('Sorry, it looks like you need to do some more work...')

    except No:
        print('OOPSIE WOOPSIE!! Uwu')

