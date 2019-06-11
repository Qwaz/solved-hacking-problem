import os.path
import pickle

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


if os.path.exists('data'):
    with open('data', 'rb') as f:
        history = pickle.load(f)
else:
    history = {}

r = remote('chainedrsa.quals2019.oooverflow.io', 5000)

r.readuntil('Seed: ')
r.read(512 + 1)

pub_ep = "-----END PUBLIC KEY-----\n"

with open('public.pem', 'w') as f:
    f.write(r.readuntil(pub_ep))
key = RSA.importKey(open("public.pem", "rb"))

N, e = key.n, key.e

l = r.readuntil('Input a string:\n').split('\n')
d0, kbits = l[0][6:].split(', ')
d0, kbits = int(d0, 16), int(kbits)
digest = l[1][8:]
enc = int(l[2][len("Encrypted Msg: "):], 16)

r.close()

history[N] = {
    'N': N,
    'e': e,
    'd0': d0,
    'kbits': kbits,
}

with open('data', 'wb') as f:
    pickle.dump(history, f)

print 'N: %d' % N
print 'e: %d' % e
print 'd0: %d' % d0
print 'kbits: %d' % kbits

for k in range(1, e):
    if k % 4096 == 0:
        print k
    d_max = (k * N + 1) // e
    d_min = d_max - (k * (1 << 1028)) // e
    d = ((d_min >> kbits) << kbits) | d0

    while d <= d_max:
        if (e * d - 1) % k != 0:
            d += (1 << kbits)
            continue

        if 0xcafebabe == pow(0xcafebabe, e * d, N):
            print hex(d)
            exit(0)

        d += (1 << kbits)
