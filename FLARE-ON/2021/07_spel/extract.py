from pwn import *

with open("spel.exe", "rb") as f:
    content = f.read()

mov_insts = content[0x2177:0x178ADF]

concat = bytearray()
for b in mov_insts[7::8]:
    concat.append(b)
concat = bytes(concat)

# ShellcodeRDI from
# https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c
with open("extract.bin", "wb") as f:
    f.write(concat[:0xB28])

with open("extract.dll", "wb") as f:
    f.write(concat[0xB28:])

with open("second_stage.dll", "wb") as f:
    start_offset = 0xB28 + 0x14EF0
    f.write(concat[start_offset : start_offset + 0x17A00])

content = bytearray(content)

patches = [
    (
        # e8 b8 02 00 00 (call command_socket)
        # b0 01 90 90 90 (mov al, 01; nop; nop; nop;)
        0x10C3,
        b"\xe8\xb8\x02\x00\x00",
        b"\xb0\x01\x90\x90\x90",
    ),
    (
        # ff b0 (call rax (SleepEx))
        # 90 90 (nop; nop;)
        0xE1E,
        b"\xff\xd0",
        b"\x90\x90",
    ),
]

for (offset, before, after) in patches:
    assert len(before) == len(after)
    real_offset = 0xB28 + 0x14EF0 + offset
    for i in range(len(after)):
        exe_offset = 0x2177 + 8 * (real_offset + i) + 7
        assert content[exe_offset] == before[i]
        content[exe_offset] = after[i]

with open("Spell.EXE", "wb") as f:
    f.write(content)
