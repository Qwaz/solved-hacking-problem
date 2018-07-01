import sys
from pwn import *

# SCTF{I_w0u1d_l1k3_70_d3v3l0p_GUI_v3rs10n_n3x7_t1m3}
GDB_HEADER = '(gdb) '
BREAK_ADDR = 0x401412
PATCH_ADDR = 0x401415


def gdb_command(cmd):
    gdb.recvuntil(GDB_HEADER)
    gdb.sendline(cmd)

gdb = process(['gdb', './dingJMax', sys.argv[1]])

gdb_command('b *0x%x' % BREAK_ADDR)

context.arch = 'amd64'
press_none = asm('mov %eax, 0')
press_d = asm('mov %eax, 0x64')
press_f = asm('mov %eax, 0x66')
press_j = asm('mov %eax, 0x6a')
press_k = asm('mov %eax, 0x6b')

for i in range(42259):
    gdb_command('c')
    gdb_command('x/gd ($rbp-0x40)')
    timing = int(gdb.recvline().strip().split()[1])

    code = press_none
    if timing % 20 == 0 and timing // 20 >= 19:
        print timing
        gdb_command('x/gx 0x%x' % (0x603280 + 8*(timing // 20 - 19)))
        str_addr = int(gdb.recvline().strip().split()[1], 16)
        print '0x%x' % str_addr
        gdb_command('x/s 0x%x' % str_addr)
        keypress = gdb.recvline().strip().split('"')[1]
        print keypress

        try:
            code = [
                press_d,
                press_f,
                press_j,
                press_k,
            ][keypress.index('o')]
        except ValueError:
            pass

    assert len(code) == 5
    for i in range(5):
        gdb_command('set *(unsigned char*)0x%x = %d' % (PATCH_ADDR + i, ord(code[i])))

gdb.interactive()
