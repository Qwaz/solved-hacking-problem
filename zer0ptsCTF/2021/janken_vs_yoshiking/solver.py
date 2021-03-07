from pwn import *


def legendre(x, p):
    # 1 or -1
    val = pow(x, (p-1) // 2, p)
    if val == p-1:
        return -1
    else:
        return val

con = remote("crypto.ctf.zer0pts.com", 10463)

con.recvuntil("Here is g: ")
g = int(con.recvuntil(", and p: ", drop=True))
p = int(con.recvline().strip())

const_syms = [legendre(i, p) for i in range(1, 4)]
if len(set(const_syms)) == 1:
    raise ValueError("P value is not supported")

# We hope x to be odd
wins_count = 0
while wins_count < 100:
    con.recvuntil("[yoshiking]: my commitment is=(")
    c1 = int(con.recvuntil(", ", drop=True))
    c2 = int(con.recvuntil(")", drop=True))

    lc1 = legendre(c1, p)
    lc2 = legendre(c2, p)
    if lc1 == lc2:
        if const_syms.count(1) == 1:
            yoshiking = const_syms.index(1)
        else:
            yoshiking = (const_syms.index(-1) + 2) % 3
    else:
        if const_syms.count(-1) == 1:
            yoshiking = const_syms.index(-1)
        else:
            yoshiking = (const_syms.index(1) + 2) % 3
    ours = (yoshiking + 2) % 3
    con.recvuntil("[system]: your hand(1-3): ")
    con.sendline(str(ours + 1))

    con.recvuntil("Your hand is ... ")
    con.recvline()
    msg = con.recvline()

    if b"Draw" in msg:
        print(f"Draw, current win: {wins_count}")
    elif b"You win!!!" in msg:
        wins_count += 1
        print(f"Win, current win: {wins_count}")
    else:
        raise ValueError("We shouldn't lose, maybe x is not odd?")

print(con.recvall().decode())
