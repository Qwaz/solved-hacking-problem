from pwn import *

# m -> { seed, N, sign }
table = {}

with open("table", "rb") as f:
    for line in f:
        seed, n, m, sign = line.split()
        seed = int(seed)
        if m not in table:
            table[m] = []

        table[m].append({
            "seed": seed,
            "n": n,
            "sign": sign,
        })

cnt = 0
while True:
    cnt += 1
    print(f"Try {cnt}")

    con = remote("crypto.ctf.zer0pts.com", 10298)

    # No padding for deterministic random state
    con.recvuntil("Message: ")
    con.sendline("A" * 125)

    con.recvuntil("pubkey = (")
    n = con.recvuntil(", ", drop=True)
    e = con.recvuntil(")\n", drop=True)

    con.recvuntil("Sign this message: ")
    msg = con.recvline().strip()

    if msg in table:
        for info in table[msg]:
            if info["n"] != n:
                continue

            con.recvuntil("Signature: ")
            con.sendline(info["sign"])

            con.recvuntil("Thank you for signing my message!")

            con.interactive()
            exit(0)

    con.close()
