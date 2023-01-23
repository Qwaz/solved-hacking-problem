from Crypto.Util.number import long_to_bytes
from pwn import *

con = remote("this-is-not-lsb.seccon.games", 8080)

con.recvuntil(b"n = ")
n = int(con.recvline().strip())
con.recvuntil(b"e = ")
e = int(con.recvline().strip())
assert e == 65537
con.recvuntil(b"flag_length = ")
flag_length = int(con.recvline().strip())
assert flag_length == 439

con.recvuntil(b"c = ")
ct = int(con.recvline().strip())


def check_coeff(x):
    con.recvuntil(b"c = ")
    q = (pow(x, e, n) * ct) % n
    con.sendline(b"%d" % q)
    return con.recvline().strip() == b"True"


# prefix = None
prefix = 0b1010011010


if prefix is None:
    intervals = []

    for prefix in range(2**9):
        flag_lo = (2**9 + prefix) << 429
        flag_hi = flag_lo + ((1 << 429) - 1)

        target_lo = 0b0011111111 << 1014
        target_hi = target_lo + ((1 << 1014) - 1)

        interval = (
            (target_lo // flag_lo) + 1,
            (target_hi // flag_hi),
        )

        assert interval[1] >= interval[0]
        intervals.append(interval)

    prev_lo = 1 << 1024

    for prefix in range(2**9):
        q = min(prev_lo - 1, intervals[prefix][1])
        if check_coeff(q):
            break

        # assert unique interval range exists
        if prefix != 0 and prefix != len(intervals) - 1:
            assert intervals[prefix - 1][0] >= intervals[prefix + 1][1]

    prefix = 2**9 + prefix

# highest 10 bit is decided
log.success(bin(prefix))

known_bit = 10
while known_bit < flag_length:
    target_bit = known_bit + 1

    zero_lo = ((prefix << 1) + 0) << (flag_length - target_bit)
    zero_hi = zero_lo + ((1 << (flag_length - target_bit)) - 1)

    one_lo = ((prefix << 1) + 1) << (flag_length - target_bit)
    one_hi = one_lo + ((1 << (flag_length - target_bit)) - 1)

    n_coeff = ((1 << (target_bit + 1013)) - (0b0011111111 << 1014)) // n + 1
    target_lo = (0b0011111111 << 1014) + n * n_coeff
    target_hi = target_lo + ((1 << 1014) - 1)

    zero_interval = (
        (target_lo // zero_lo) + 1,
        (target_hi // zero_hi),
    )
    
    one_interval = (
        (target_lo // one_lo) + 1,
        (target_hi // one_hi),
    )

    if check_coeff(zero_interval[1]):
        prefix = prefix * 2
    else:
        assert check_coeff(one_interval[1])
        prefix = prefix * 2 + 1
    known_bit += 1

    print(bin(prefix))

# SECCON{WeLC0me_t0_tHe_MirRoR_LaNd!_tHIs_is_lSb_orAcLe!}
print(long_to_bytes(prefix).decode())
