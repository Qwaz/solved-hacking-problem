from pwn import *

con = listen(9798)
con.wait_for_connection()

con.recvuntil("vvvv Here's some binary data. Figure it out.\n\n\n")
pyc = con.recvuntil("\n\n^^^^ Here's some binary data. Figure it out.", drop=True)

with open("out.pyc", "wb") as f:
    f.write(pyc)
