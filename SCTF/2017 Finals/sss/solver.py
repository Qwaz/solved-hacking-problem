import base64
import json

from pwn import *

p = remote('sss.eatpwnnosleep.com', 18878)

a = {
    'apikey' : 'aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33',
}

p.send(json.dumps(a))

files = ['asttree.c', 'valenv.h']

for filename in files:
    with open(filename) as f:
        content = f.read()
    p.recvuntil('finish\n')
    p.sendline(filename)
    p.recvuntil('base64 : ')
    p.sendline(base64.b64encode(content))

p.interactive()
