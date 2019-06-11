# V-R]]V-RR]V--R]V
from pwn import *

with open('resource/xtszswemcwohpluqmi', 'rb') as f:
    data = f.read()


a = [ord(data[0]) ^ 0x90, ord(data[1]) ^ 0x90, ord(data[2]) ^ 0x90, ord(data[3]) ^ 0x90]

code = ''
for i in range(len(data)):
    code += chr(ord(data[i]) ^ a[i % 4])
    if i % 4 == 3:
        t = (a[3] << 24) + (a[2] << 16) + (a[1] << 8) + a[0]
        t += 0x31333337
        t &= 0xffffffff

        a[3] = (t >> 24) & 0xff
        a[2] = (t >> 16) & 0xff
        a[1] = (t >> 8) & 0xff
        a[0] = t & 0xff

print(disasm(code))

with open('steps/step3.raw', 'wb') as f:
    f.write(code)
