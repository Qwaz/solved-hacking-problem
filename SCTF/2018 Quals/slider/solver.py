'''
1)
enc
  0 1 0 2,0 1 0 2,0 1 0 2,0 1 0 2
dec
2 0 1 0,2 0 1 0,2 0 1 0,2 0 1 0

Find slid pair for K2

2)
enc
0 1 0 2,0 1 0 2,0 1 0 2,0 1 0 2
dec
  2 0 1 0,2 0 1 0,2 0 1 0,2 0 1 0

Find slid pair for K1 ^ K2
(Complementation Slide)

3)
Brute-Force K0
'''

from binascii import hexlify, unhexlify
import os

from Crypto.Cipher import AES
from pwn import *
import pymp

cipher = AES.new(''.join([chr(c) for c in range(16)]), AES.MODE_ECB)


def bxor(a, b):
    return ''.join((chr(ord(x) ^ ord(y)) for x, y in zip(a, b)))


def encrypt(msg):
    assert len(msg) == 2
    return cipher.encrypt(msg + '\x00' * 14)[:2]


def feistel(m, k):
    if len(m) != 4:
        return None

    l, r = m[0:2], m[2:4]

    for rkey in k * 4:
        l, r = r, bxor(l, table[bxor(r, rkey)])

    return r + l


def check_enc(k0, k1, k2, m):
    k = (k0, k1, k0, k2)
    return feistel(m, k)


def check_dec(k0, k1, k2, m):
    k = (k2, k0, k1, k0)
    return feistel(m, k)


def read_msg(tube):
    return unhexlify(tube.recvline().strip())


def send_enc(tube, l, r):
    p.sendline('enc ' + hexlify(l) + hexlify(r))
    return read_msg(tube)


def send_dec(tube, l, r):
    p.sendline('dec ' + hexlify(l) + hexlify(r))
    return read_msg(tube)


table = {}
reverse_table = {}

for c in range(256 * 256):
    c = p16(c)
    reverse_table[c] = []

for c in range(256 * 256):
    c = p16(c)
    result = encrypt(c)
    table[c] = result
    reverse_table[result].append(c)

count = 0
context.log_level = 'warning'

while True:
    count += 1
    print 'Try %d...' % count

    enc_pair = {}
    dec_pair = {}

    p = remote('slider.eatpwnnosleep.com', 6884)
    p.recvuntil('Commands: [enc | dec | guess] <hxstr>\n')

    fix = os.urandom(2)
    for i in range(2**8):
        r = os.urandom(2)

        enc_pair[r+fix] = send_enc(p, r, fix)
        dec_pair[r+fix] = send_dec(p, r, fix)
        enc_pair[fix+r] = send_enc(p, fix, r)
        dec_pair[fix+r] = send_dec(p, fix, r)

    K0 = None
    K1 = None
    K2 = None

    for (enc_in, enc_out) in enc_pair.items():
        for (dec_in, dec_out) in dec_pair.items():
            L = dec_in[:2]
            R = dec_in[2:]
            M = dec_out[:2]
            N = dec_out[2:]

            L_ = enc_in[:2]
            R_ = enc_in[2:]
            M_ = enc_out[:2]
            N_ = enc_out[2:]

            if R == L_ and M == N_:
                # M_ = N ^ f(M ^ K2)
                # R_ = L ^ f(R ^ K2)
                for r1 in reverse_table[bxor(M_, N)]:
                    K2_cand1 = bxor(r1, M)
                    for r2 in reverse_table[bxor(R_, L)]:
                        K2_cand2 = bxor(r2, R)
                        if K2_cand1 == K2_cand2:
                            K2 = K2_cand1

            if K2 is not None:
                break
        if K2 is not None:
            break
    if K2 is None:
        p.close()
        continue

    for (enc_in, enc_out) in enc_pair.items():
        for (dec_in, dec_out) in dec_pair.items():
            L = enc_in[:2]
            R = enc_in[2:]
            M = enc_out[:2]
            N = enc_out[2:]

            L_ = dec_in[:2]
            R_ = dec_in[2:]
            M_ = dec_out[:2]
            N_ = dec_out[2:]

            if R == L_ and M == N_:
                # D = K1 ^ K2
                # L ^ f(R ^ K0) = R_ ^ D
                # N ^ D = M_ ^ f(N_ ^ K0)
                # N ^ R_ = L ^ M_ ^ f(R ^ K0) ^ f(N_ ^ K0)
                for K0 in range(256 * 256):
                    K0 = p16(K0)
                    if bxor(table[bxor(R, K0)], table[bxor(N_, K0)]) == \
                        bxor(bxor(N, M_), bxor(L, R_)):
                        D_cand1 = bxor(bxor(L, R_), table[bxor(R, K0)])
                        D_cand2 = bxor(bxor(N, M_), table[bxor(N_, K0)])
                        if D_cand1 == D_cand2:
                            K1_cand = bxor(D_cand1, K2)

                            all_correct = True
                            for (enc_in, enc_out) in enc_pair.items()[:10]:
                                if check_enc(K0, K1_cand, K2, enc_in) != enc_out:
                                    all_correct = False
                                    break

                            for (dec_in, dec_out) in dec_pair.items()[:10]:
                                if check_dec(K0, K1_cand, K2, dec_in) != dec_out:
                                    all_correct = False
                                    break

                            if all_correct:
                                K1 = K1_cand
                                break

            if K1 is not None:
                break
        if K1 is not None:
            break
    if K1 is None:
        p.close()
        continue

    print hexlify(K0+K1+K2)

    p.sendline('guess ' + hexlify(K0+K1+K2))
    result = p.recvall().strip()
    p.close()

    if 'SCTF' in result:
        print result
        break
