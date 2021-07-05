import os

with open("md5.o", "rb") as f:
    code = f.read()[0x40:]
    code = code[: code.find(b"\x90\x90\x90\x90\x90")]

code += b"\x66" * (0x2000 - len(code) - 2)
code += b"\x89\xE5"

assert len(code) == 8192

with open("payload", "wb") as f:
    f.write(code)

# pwntools doesn't work for some reason...
os.system("nc 111.186.59.29 10086 < payload")
