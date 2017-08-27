from base64 import b64encode as b64e

from pwn import *

p = remote('libfilesys.eatpwnnosleep.com', 10000)

p.recvuntil('api_key: ')
p.recvn(10)

p.sendline('aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33')
if 'Try' in p.recvn(20):
    s = p.recvn(5)
    print s[:s.index('.')]
    exit(0)

p.recvuntil('base64 : ')
p.recvn(10)

with open('libfilesys_patched.so', 'rb') as f:
    content = f.read()

p.sendline(b64e(content))
p.interactive()
