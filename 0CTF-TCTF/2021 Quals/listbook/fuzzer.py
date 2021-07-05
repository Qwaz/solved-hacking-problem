import random
import os
from pwn import *


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

    occupied[count] = True
    return count


def delete_book(index):
    con.recvuntil(b">>")
    con.sendline("2")
    con.recvuntil("index>")
    con.sendline(str(index))
    occupied[index] = False


def show_book(index):
    con.recvuntil(b">>")
    con.sendline("3")
    con.recvuntil("index>")
    con.sendline(str(index))
    occupied[index] = False


def rand_name():
    while True:
        name = os.urandom(16)
        if b"\x0a" in name:
            continue
        return name


os.environ["LD_PRELOAD"] = "./libc-2.31.so"

while True:
    occupied = [False for _ in range(16)]
    con = process("./listbook")

    sequence = []

    try:
        while True:
            indices = list(
                map(lambda t: t[0], filter(lambda t: t[1], enumerate(occupied)))
            )
            if len(indices) > 0:
                index = random.choice(indices)

                sel = random.randint(1, 3)
                if sel == 1:
                    name = rand_name()
                    index = create_book(name, "abc")
                    sequence.append((1, name, "abc", index))
                elif sel == 2:
                    sequence.append((2, index))
                    delete_book(index)
                else:
                    sequence.append((3, index))
                    show_book(index)
            else:
                name = rand_name()
                index = create_book(name, "abc")
                sequence.append((1, name, "abc", index))
    except Exception:
        con.close()

    if len(sequence) < 100:
        break

print(sequence)
print(len(sequence))

while True:
    found = False
    for i in range(len(sequence)):
        test_sequence = sequence[:i] + sequence[i + 1 :]

        occupied = [False for _ in range(16)]
        con = process("./listbook")

        try:
            for input in test_sequence:
                if input[0] == 1:
                    create_book(input[1], input[2])
                elif input[0] == 2:
                    delete_book(input[1])
                else:
                    show_book(input[1])
            con.close()
        except Exception:
            found = True
            con.close()

        if found:
            sequence = test_sequence
            break

    if not found:
        break

print(sequence)
print(len(sequence))
