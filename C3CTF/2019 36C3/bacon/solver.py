import subprocess

from pwn import *

c = remote('78.47.89.248', 1952)

target = c.recvline().strip()
print target

ans = subprocess.check_output(
    ['../pypy3.6-v7.3.0-linux64/bin/pypy3', 'brute.py', target]).strip()
print ans

c.sendline(ans)

print c.recvall()
