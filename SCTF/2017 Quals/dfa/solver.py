from pwn import *

import base64

p = remote('dfa.eatpwnnosleep.com', 9999)

p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()

p.sendline('auto.c')

with open('auto.patch.c', 'r') as f:
    content = f.read()

p.recvuntil('base64 : ')
p.sendline(base64.b64encode(content))

print p.recvall()
