from pwn import *

import re

with open('ai.min.lua') as f:
    content = f.read()
content = content.replace('\t', '')

s = {}
e = {}

SZ = 7
M = 0x7FFFFFFF
mod = [0, 0, 0, 0, 0, 0, 0]
asum = [0, 0, 0, 0, 0, 0, 0]

for i in range(10000):
    x = pow(48271, i, M)
    if x < 1000000:
        print '%6d %10d' % (i, x)

p = remote('13.113.99.240', 50216)

p.recvuntil('AI:\n')
p.send(content)

p.interactive()
