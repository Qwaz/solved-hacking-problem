from pwn import *

with open("solver.lua") as f:
    sol = f.read()

# hashcash -b 25 -m -r stegasaurus >> hashes
with open("hashes") as f:
    hashes = f.read()

with open("hashes", "w") as f:
    f.write('\n'.join(hashes.split('\n')[1:]))
current_hash = hashes.split('\n')[0]

p = remote("stegasaurus.pwni.ng", 1337)

p.recvuntil("> ")
p.sendline(current_hash)

p.recvuntil("send your file\n")
p.send(sol)
p.shutdown()

print(p.recvall())
