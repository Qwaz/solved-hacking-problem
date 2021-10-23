import binascii
import json
from pwn import *
import os
from os import path
import glob

elf = ELF("./AntiochOS")

profiles = {}

for i in range(30):
    profile_addr = 0x402000 + i * 12
    name_crc = u32(elf.read(profile_addr, 4))
    order = u32(elf.read(profile_addr + 8, 4))

    profiles[name_crc] = order


char_map = "V',`)(//\\\\\\||||||||||||_______________" + "." * (256 - 0x26)

latest = [(None, 0) for _ in range(26)]

for dir_name in glob.glob("antioch/*"):
    if not path.isdir(dir_name):
        continue

    with open(dir_name + "/json") as f:
        metadata = json.loads(f.read())

    if "author" not in metadata:
        continue

    name_crc = binascii.crc32(metadata["author"].encode() + b"\n")
    author_order = profiles[name_crc]

    if name_crc not in profiles:
        print(f"{metadata['author']} not found")
        exit(1)

    os.system(f"tar -xf {dir_name}/layer.tar -C {dir_name}")

    dir_abspath = path.abspath(dir_name)

    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
        filename = f"{dir_name}/{c}.dat"
        if path.exists(filename):
            with open(filename, "rb") as f:
                content = f.read()
            
            if latest[i][1] < author_order:
                latest[i] = (content, author_order)

buf = bytearray([0 for _ in range(4096)])

for content, _ in latest:
    for i, b in enumerate(content):
        buf[i] ^= b

for x in range(256):
    line = ""
    for c in buf[x * 16 : (x + 1) * 16 - 1]:
        line += char_map[c]
    print(line)

# Five-Is-Right-Out@flare-on.com
