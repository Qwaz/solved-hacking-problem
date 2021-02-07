from pwn import *
import gmpy2

con = listen(9798)
con.wait_for_connection()

e = 65537

con.recvuntil("3) Get encrypted flag\n\n")

N = 0

for num in (2, 3, 5, 7, 11):
    con.recvuntil("> ")
    con.sendline("1")

    powered = num ** e
    con.recvuntil("> ")
    con.sendline(str(num))

    actual = int(con.recvline().strip())

    if N == 0:
        N = powered - actual
    else:
        N = int(gmpy2.gcd(N, powered - actual))

print("N: %d\n" % N)

con.recvuntil("> ")
con.sendline("3")

con.recvuntil("not that you can do much with it:\n")
flag_int = int(con.recvline().strip())

double_flag_enc = flag_int * pow(2, e, N) % N

con.recvuntil("> ")
con.sendline("2")

con.recvuntil("> ")
con.sendline(str(double_flag_enc))

double_flag = int(con.recvline().strip())
two_inv = int(gmpy2.invert(2, N))
flag = double_flag * two_inv % N

flag_bytes = flag.to_bytes(flag.bit_length() // 8 + 1, byteorder='big')

print(flag_bytes.decode())
