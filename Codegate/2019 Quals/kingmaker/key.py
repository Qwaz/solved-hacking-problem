from pwn import *

context.arch = 'amd64'

PROLOGUE = '''
    push rbp
    mov rbp, rsp
    sub rsp, {}
    mov [rbp-{}], rdi
'''

def find_key(stack_size, s):
    prologue = asm(PROLOGUE.format(stack_size, stack_size-8))
    result = ''
    for i in range(min(len(s), len(prologue))):
        result += chr(ord(s[i]) ^ ord(prologue[i]))
    return result


def dehex(s):
    return ''.join(map(lambda s: chr(int(s, 16)), s.split(' ')))


print find_key(0x20, dehex('39 07 FF D6 24 CC 9A 13 24 C6 0B DB 08 07 FD 37 49 67 76'))
print find_key(0x20, dehex('11 78 E5 D4 0C B3 80 11 0C B9 11 D9 20 78 E7 35 61 18 6C 31 44 78 E5 74 BC 01 AC'))
print find_key(0x20, dehex('1D 3D C7 82 1A DA B8 11 25 BA 35 9D 2A 2F D9 5D 71 19 6D 33 48 3D C7 22 AA 68 94 8E 45 7F'))
print find_key(0x20, dehex('13 78 FC B7 1B B0 8D 73 78 E7 3B D8 11 1A D8 37 44 7B 30 6E 46 78'))
print find_key(0x20, dehex('01 79 E2 B1 7C E8 B8 10 03 E2 29 D9 0F 1C BF 6F 71 18 4B 6B 54'))
