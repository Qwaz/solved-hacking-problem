import struct
def reg(x):
    return 1 << ['r0', 'r1', 'r2', 'r3', 'sp', 'pc'].index(x)

def asm(lines):
    labels = {}
    pc = 0
    handlers = dict(
        push=lambda a: [2, 0, reg(a), 0],
        pop=lambda a: [2, reg(a), 0, 0],
        ldi=lambda dst, a: [1, reg(dst), *struct.pack("<H", eval(a, labels))],
        str=lambda a, b: [8, reg(a), reg(b), 0],
        syscall=lambda sysno, dst: [0x80, 1 << int(sysno), reg(dst), 0],
        add=lambda a,b: [4, reg(a), reg(b), 0],
        branch=lambda a:[0x20,0,reg(a), 0],
        load=lambda a, b: [0x10, reg(a), reg(b), 0]
    )

    code = []
    for line in lines.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.endswith(':'):
            labels[line[:-1]] = pc
            continue
        pc += 4
        code.append(line)
    print(labels)

    raw = []

    for line in code:
        if line.lower() == "nop":
            raw += [0xff, 0xff, 0xff, 0xff]
        elif line.lower() == "flag":
            raw += [ord("f"), ord("l"), ord("a"), ord("g"), 0, 1, 0, 0]
        else:
            mnem, args = line.split(' ', 1)
            args = [arg.strip() for arg in args.split(',')]
            print(mnem, args)
            raw += handlers[mnem](*args)
        assert len(raw) % 4 == 0

    raw = bytes(raw)
    return raw

shellcode = """
start:
ldi r1, 0
add r1, pc
ldi r3, path - start - 8
add r1, r3
ldi r0, 0
ldi r2, 0
syscall 0, r0

ldi r1, 0
add r1, sp
ldi r3, 32
push r3
ldi r2, 0
add r2, sp
syscall 1, r3

ldi r0, 1
syscall 3, r3
ldi r0, 0
pop r3

path:
flag
"""

print("[Original shellcode]")
print(shellcode)
open('asm', 'wb').write(asm(shellcode))

base = 0xb28
pc = base

adjusted = ""
cnt = 5
for line in shellcode.split("\n"):
    line = line.strip()
    if not line:
        continue

    adjusted += line + "\n"

    if line.endswith(':'):
        continue

    cnt -= 1
    pc += 4

    if cnt == 0:
        adjusted += "push r3\n"
        adjusted += f"ldi r3, {pc + 4 * 9}\n"
        adjusted += "branch r3\n"

        adjusted += "nop\n" * 6
        adjusted += "pop r3\n"

        pc += 4 * 10
        cnt = 4

# Manually check that the last flag is in correct position
print("[Adjusted shellcode]")
print(adjusted)
open('asm_adjusted', 'wb').write(asm(adjusted))
