from z3 import *

result = []

with open("output_processed.txt", "r") as f:
    pending = None

    for line in f:
        if line.startswith("r7 = r7 + "):
            pending["ops"].append(line.strip()[10:])
        elif line.startswith("r7 = ") and line != "r7 = *r2\n":
            if pending is not None:
                result.append(pending)
            pending = {
                "target_val": (1 << 64) - int(line.strip()[5:], 16),
                "ops": []
            }

result.append(pending)

out = [BitVec(f"out{i}", 8) for i in range(24)]
serial_suffix = [BitVec(f"serial{i}", 8) for i in range(16, 28)]

def handle_op(op_txt, v):
    if op_txt.endswith(" * r2"):
        coeff = int(op_txt[:-5])
        return coeff * ZeroExt(16, v)
    else:
        opcode = op_txt[:-8]
        imm = int(op_txt[-3:-1], 16)
        if opcode == "and":
            return ZeroExt(16, v & imm)
        if opcode == "xor":
            return ZeroExt(16, v ^ imm)
        if opcode == "or":
            return ZeroExt(16, v | imm)
        if opcode == "rol":
            return ZeroExt(16, RotateLeft(v, imm))
        if opcode == "ror":
            return ZeroExt(16, RotateRight(v, imm))
        if opcode == "shl":
            return ZeroExt(16, v << imm)
        if opcode == "shr":
            return ZeroExt(16, LShR(v, imm))

for cond in result:
    print(cond)

# Part 1
solver = Solver()

for cond in result[:24]:
    acc = BitVecVal(0, 24)
    for (i, op) in enumerate(cond["ops"]):
        acc += handle_op(op, out[i])
    solver.add(cond["target_val"] == acc)

# rc4(CT): 864808
solver.add(out[0] == 0x86)
solver.add(out[1] == 0x48)
solver.add(out[2] == 0x08)

# rc4(F{): ed1e31
solver.add(out[3] == 0xed)
solver.add(out[4] == 0x1e)
solver.add(out[5] == 0x31)

if solver.check() == sat:
    print("SAT!")
    m = solver.model()

    for i in range(len(out)):
        print(f"out[{i}] = {m[out[i]].as_long()}")
else:
    print("UNSAT...")

    """
    out[0] = 134
    out[1] = 72
    out[2] = 8
    out[3] = 237
    out[4] = 30
    out[5] = 49
    out[6] = 89
    out[7] = 229
    out[8] = 232
    out[9] = 232
    out[10] = 228
    out[11] = 17
    out[12] = 242
    out[13] = 81
    out[14] = 243
    out[15] = 1
    out[16] = 225
    out[17] = 114
    out[18] = 46
    out[19] = 224
    out[20] = 109
    out[21] = 91
    out[22] = 103
    out[23] = 182
    """


# Part 2
solver = Solver()

for cond in result[24:]:
    acc = BitVecVal(0, 24)
    for (i, op) in enumerate(cond["ops"]):
        acc += handle_op(op, serial_suffix[i])
    solver.add(cond["target_val"] == acc)

if solver.check() == sat:
    print("SAT!")
    m = solver.model()

    s = ""
    for i in range(len(serial_suffix)):
        s += chr(m[serial_suffix[i]].as_long())

    # 3_3LF_m4g1c}
    print(s)
else:
    print("UNSAT...")
