import sys
from binascii import hexlify
from hashlib import md5
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from Crypto.Util.asn1 import DerSequence
from Crypto.IO import PEM
from pwn import *


def import_key(data):
    der, marker, _ = PEM.decode(data)
    ints = DerSequence().decode(der)

    if not marker.startswith('myDSA'):
        raise ValueError('Invalid format')

    return dict(zip(('p', 'q', 'g', 'y', 'x'), map(Integer, ints)))


with open('server_1_priv.pem') as f:
    server1 = import_key(f.read())

with open('server_2_pub.pem') as f:
    server2 = import_key(f.read())

if len(sys.argv) < 2:
    print ('Usage: %s <stage>' % sys.argv[0])
    exit(0)

BLOCK = 512 // 8
TMP_ID = 'qwaz'

mx = 'admin'
hx = b2l(md5(mx).digest())

stage = int(sys.argv[1])
if stage == 1:
    k = 123
    rx = Integer(pow(int(server1['g']), k, int(server1['p']))) % server1['q']
    sx = Integer(k).inverse(server1['q']) * (Integer(hx) + server1['x'] * rx) % server1['q']

    p = remote('saltydsa.eatpwnnosleep.com', 12345)
    p.recvuntil('1) register 2) login 3) exit\n')
    p.sendline('2')
    p.recvuntil('name as hex encoded string.\n')
    p.sendline(hexlify(mx))
    p.recvuntil('format.\n')
    p.sendline('%d %d' % (rx, sx))

    # SCTF{You_really_
    p.interactive()
elif stage == 2:
    p = remote('saltydsa.eatpwnnosleep.com', 12345)
    p.recvuntil('1) register 2) login 3) exit\n')
    p.sendline('1')
    p.recvuntil('name as hex encoded string.\n')
    p.sendline(hexlify(TMP_ID))
    p.recvuntil('Plz keep it secret.\n')
    r0, s0 = map(int, p.recvline().strip().split())

    # salt + 'A'*36 + md5(x)
    # k = s^-1 * (m + xr)
    md5_status = l2b(int(Integer(s0).inverse(server1['q']) *
                         (Integer(b2l(md5(TMP_ID).digest())) + server1['x'] * Integer(r0)) %
                         server1['q']))

    # 8a6ed196cf0342aed5e65039ef6b92e7
    # use https://github.com/s1fr0/md5-tunneling
    print hexlify(md5_status)

    status_arr = [
        u32(md5_status[0:4]),
        u32(md5_status[4:8]),
        u32(md5_status[8:12]),
        u32(md5_status[12:16]),
    ]

    print ' '.join(map(lambda n: '0x%08x' % n, status_arr))
elif stage == 3:
    with open('collision1_md5_E2B02FCC.bin') as f:
        col1 = f.read()
    with open('collision2_md5_E2B02FCC.bin') as f:
        col2 = f.read()

    prefix = TMP_ID + md5(l2b(int(server1['x']))).digest()
    orig_len = len(prefix) + 12
    prefix += '\x80' + '\x00' * (BLOCK - orig_len - 9) + p64(orig_len * 8)

    m1 = prefix + col1
    h1 = b2l(md5(m1).digest())

    m2 = prefix + col2
    h2 = b2l(md5(m2).digest())

    p = remote('saltydsa.eatpwnnosleep.com', 54321)
    p.recvuntil('1) register 2) login 3) exit\n')
    p.sendline('1')
    p.recvuntil('name as hex encoded string.\n')
    p.sendline(hexlify(m1))
    p.recvuntil('Plz keep it secret.\n')
    r1, s1 = map(int, p.recvline().strip().split())

    p.recvuntil('1) register 2) login 3) exit\n')
    p.sendline('1')
    p.recvuntil('name as hex encoded string.\n')
    p.sendline(hexlify(m2))
    p.recvuntil('Plz keep it secret.\n')
    r2, s2 = map(int, p.recvline().strip().split())

    print r1, s1
    print r2, s2
    assert r1 == r2

    # DSA attack
    # https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/
    # https://rdist.root.org/2009/05/17/the-debian-pgp-disaster-that-almost-was/

    k = int(Integer(h1 - h2) * Integer(s1 - s2).inverse(server2['q']) % server2['q'])
    x = int(Integer((s1 * k) - h1) * Integer(r1).inverse(server2['q']) % server2['q'])

    sx = int(Integer(hx + x * r1) * Integer(k).inverse(server2['q']) % server2['q'])

    p.recvuntil('1) register 2) login 3) exit\n')
    p.sendline('2')
    p.recvuntil('name as hex encoded string.\n')
    p.sendline(hexlify(mx))
    p.recvuntil('format.\n')
    p.sendline('%d %d' % (r1, sx))

    # have_to_generate_k_in_DSA_carefully}
    p.interactive()
