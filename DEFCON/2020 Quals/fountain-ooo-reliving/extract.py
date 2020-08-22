import golly as g

RIGHT = -1841025
TOP = -6854568
SIZE = 22528

MODE = ("", "A", "B", "C")
OPCODE = (
    "MNZ",
    "MLZ",
    "ADD",
    "SUB",
    "AND",
    "OR",
    "XOR",
    "ANT",
    "SL",
    "SRL",
    "SRA",
    "UNKNOWN_11",
    "UNKNOWN_12",
    "UNKNOWN_13",
    "UNKNOWN_14",
    "UNKNOWN_15",
)


def wrap_i16(num):
    return num if num < 32768 else num - 65536

raw = ""
disasm = ""

for pc in range(120):
    num = 0
    for y in range(58):
        current_bit = g.getcell(RIGHT - pc * SIZE, TOP + y * SIZE)
        raw += str(current_bit)
        num = num * 2 + current_bit
    raw += "\n"

    opcode = OPCODE[num & 0b1111]
    num = num >> 4

    reg1 = wrap_i16(num & ((1 << 16) - 1))
    num = num >> 16
    reg1_mode = MODE[num & 0b11]
    num  = num >> 2

    reg2 = wrap_i16(num & ((1 << 16) - 1))
    num = num >> 16
    reg2_mode = MODE[num & 0b11]
    num  = num >> 2

    reg3 = wrap_i16(num & ((1 << 16) - 1))
    num = num >> 16
    reg3_mode = MODE[num & 0b11]
    num  = num >> 2

    disasm += "{}. {} {}{} {}{} {}{};\n".format(
        pc, opcode, reg1_mode, reg1, reg2_mode, reg2, reg3_mode, reg3
    )

with open("raw.txt", "w") as f:
    f.write(raw)
    
with open("disasm.txt", "w") as f:
    f.write(disasm)

g.note('check "raw.txt" and "disasm.txt"')

"""
After extracting, change
1. XOR 0 0 2;
to
1. MLZ -1 61463 1;

Then run the code at http://play.starmaninnovations.com/qftasm/

OOO{in_this_life___youre_on_your_own}
"""
