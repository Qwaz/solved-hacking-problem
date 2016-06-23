#!/usr/bin/env python

import hashlib
from pwn import *

CHAR_SET = '1234567890abcdefghijklmnopqrstuvwxyz-_\x00'

def try_login(id, pw):
    p = remote('localhost', 9006)
    p.recvuntil('ID\n')
    p.sendline(id)
    p.recvuntil('PW\n')
    p.sendline(pw)
    line = p.recvline()
    p.recvall()
    p.close()

    return line[24:-2]

context.log_level = "error"

cookie_len = len(try_login('', ''))/2 - 2
print 'cookie length: %d' % cookie_len

BLOCK_SIZE = 16
found = ''

i = 0
while True:
    before_len = 2 + i
    id = '-' * (BLOCK_SIZE - 1 - before_len % BLOCK_SIZE)
    after_len = len(id) + before_len

    block_index = after_len // BLOCK_SIZE
    original_block = try_login(id, '')[block_index * BLOCK_SIZE * 2 : (block_index + 1) * BLOCK_SIZE * 2]

    for c in CHAR_SET:
        try_block = try_login(id, '-' + found + c)[block_index * BLOCK_SIZE * 2 : (block_index + 1) * BLOCK_SIZE * 2]
        if try_block == original_block:
            found += c
            print 'Found! %s' % found
            break

    if c == '\x00':
        break
    i += 1

p = remote('localhost', 9006)
p.recvuntil('ID\n')
p.sendline('admin')
p.recvuntil('PW\n')
p.sendline(hashlib.sha256('admin'+found).hexdigest())
line = p.recvline()
print p.recvall()
p.close()
