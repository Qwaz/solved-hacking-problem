# by jinmo123
import subprocess
import time
import struct

# Static analysis (?)
data = open("chals/chal-test", "rb").read()
offset = data[data.find(b"\x48\x63", data.find(b"\xb0\x00\xff") - 0x20) + 4 :][:4]
offset = struct.unpack("<L", offset)[0]
print("offset will be at", hex(offset))

# Dynamic analysis (shellcode, memory reading)
p = subprocess.Popen(["chals/chal-test"], stdin=subprocess.PIPE)

time.sleep(3)

base = f"/proc/{p.pid}/"
maps = list(open(base + "maps"))
rwx = [int(line.split("-")[0], 16) for line in maps if "rwx" in line][0]
rwx_end = [int(line.split(" ")[0].split("-")[1], 16) for line in maps if "rwx" in line][
    0
]

print(hex(rwx), hex(rwx_end))

mem = open(base + "mem", "rb")
mem.seek(rwx)
code = mem.read(rwx_end - rwx)

mem.seek(offset)
offset = struct.unpack("<L", mem.read(4))[0]
mem.close()

print("Code:", bytes(code)[:100])
print("Offset:", hex(offset))
p.kill()
