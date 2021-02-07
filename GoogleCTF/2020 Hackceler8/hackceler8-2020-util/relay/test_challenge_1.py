from pwn import *

con = listen(9798)
con.wait_for_connection()

con.recvuntil("Oh! Look what time it is: ")
start_time = int(con.recvline().strip())

to_add = 38
while True:
    con.recvuntil("Now, tell me the number I'm thinking about: ")
    con.sendline(str(start_time + to_add))
    to_add += 1
    if b"Hahaha" not in con.recvline():
        break
