import binascii
from pwn import *

'''
   0:   48 8d 85 f0 fe ff ff    lea    rax,[rbp-0x110]
   7:   48 89 c7                mov    rdi,rax
   a:   b8 00 00 00 00          mov    eax,0x0
   f:   e8 0a ea ff ff          call   0xffffffffffffea1e
  14:   90                      nop
'''

context.arch = 'amd64'
code = '48 8D 85 F0 FE FF  FF 48 89 C7 B8 00 00 00 00 E8 0A EA FF FF 90'
code = binascii.unhexlify(code.replace(' ', ''))

print binascii.hexlify(code)
print disasm(code)

payload = asm('mov edx,eax')
# payload = asm('mov rdx,rax')
payload += asm('lea rsi,[rbp-0x110]')
payload += asm('xor edi,edi')
payload += asm('inc rdi')
payload += '\xe8' + p32((0xec0 - (0x2492 + len(payload) + 5)) & 0xffffffff)
payload += '\x90' * (len(code) - len(payload))

print binascii.hexlify(payload)
print disasm(payload)
