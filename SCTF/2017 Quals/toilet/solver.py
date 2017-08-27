from Crypto.Util.number import bytes_to_long as s2i
from Crypto.Util.number import long_to_bytes as i2s
from Crypto.Cipher import AES
from Crypto.Hash import MD5

import base64
import binascii
import requests


def gf_2_128_mul(x, y):
    # GF(2^128) : 1 + a + a^2 + a^7 + a^128
    assert (x | y) < (1 << 128)
    res = 0
    for i in range(128):
        if y & (1 << i):
            res ^= x
        x = x << 1
        if x & 0x100000000000000000000000000000000L:
            x ^= 0x100000000000000000000000000000087L
    return res


def gf_pow(x, p):
    res = 0
    while p:
        if p & 1:
            res ^= x
        x = gf_2_128_mul(x, x)
        p = p >> 1
    return res


def uHash(message, key):
    res = 0
    plen = 16 - (len(message) % 16)
    message += chr(plen) * plen
    for i in xrange(len(message) / 16):
        blk = s2i(message[16 * i: 16 * i + 16])
        res = gf_2_128_mul(blk ^ res, key)
    return res


def get_cookie(name):
    r = requests.get('http://toilet.eatpwnnosleep.com/login/?name={}'.format(name))
    return base64.b64decode(r.history[0].cookies['session'])

#                   prefix: 29 | <- Control Start
# {"is_admin": false, "name": "Test"}
while True:
    c1 = get_cookie('   \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    c2 = get_cookie('   \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    if c1[:16] == c2[:16]:
        break

i1 = s2i(c1[-16:])
i2 = s2i(c2[-16:])

key_square = i1 ^ i2

'''
sqrt x = x ^ (2 ^ 127)
Therefore, we can get s2i(self.key)
'''

print "key * key = %d" % key_square
key = gf_pow(key_square, 2 ** 127)
print "key = %d" % key
key_str = i2s(key)
prp = AES.new(key_str).encrypt

nonce = "0123456789abcdef"
msg = '{"is_admin": true, "name": "Qwaz"}'

sign = i2s(uHash(msg, key) ^ s2i(prp(nonce))).ljust(16, '\x00')
fake_cookie = base64.b64encode(nonce + msg + sign)

print 'Use this cookie: %s' % fake_cookie
