from pwn import *

con = listen(9798)
con.wait_for_connection()

con.recvuntil("Send the following binary data my way: ")
data = b"".join(map(lambda s: bytes([int(s, 16)]), con.recvline().strip().split(b" ")))
con.send(data)
