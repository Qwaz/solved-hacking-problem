from binascii import unhexlify
from time import sleep

from pwn import *

con = process("chals/chal-test")

sleep(1)

# gdb.attach(con.pid)

con.send(unhexlify("57 04 ae b9 c0 c1 96 6e".replace(" ", "")))
print(con.recvall().strip().decode())
