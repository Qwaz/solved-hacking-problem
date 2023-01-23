from binascii import unhexlify

rand_arr = b"Welcome to SECCON 2022"

flag = unhexlify(
    (
        "04 20 2F 20 20 23 1E 59  44 1A 7F 35 75 36 2D 2B"
        + "11 17 5A 03 6D 50 36 07  15 3C 09 01 04 47 2B 36"
        + "41 0a 38"
    ).replace(" ", "")
)

flag = bytearray(flag)
flag[0] ^= 0x57

for state in range(1, len(flag)):
    t = state // 0x16 + 2 * (
        state // 0x16 + (((((0x2E8BA2E8BA2E8BA3 * state) >> 64) & 0xFFFFFFFFFFFFFFFC)))
    )
    flag[state] ^= rand_arr[state - 2 * t]

print(flag.decode())
