from abc import ABC
from collections import defaultdict
from enum import Enum
from multiprocessing import Pool
from capstone import *
from pwn import *
from z3 import *

import subprocess


class Arch(Enum):
    PE32 = 1
    POWER32 = 2
    POWER64 = 3
    ALPHA64 = 4
    EXE_86_64 = 5
    LIB_86_64 = 6
    M68K = 7
    MIPS64 = 8
    MIPS32_LE = 9
    MIPS32_BE = 10
    SPARC = 11
    RENESAS = 12
    ARM64 = 13
    ARM32 = 14
    S390 = 15
    HP_PA = 16
    RISCV64 = 17


name_to_arch = {
    "ELF 32-bit MSB executable, PowerPC or cisco 4500": Arch.POWER32,
    "ELF 64-bit MSB executable, 64-bit PowerPC or cisco 7500": Arch.POWER64,
    "ELF 64-bit LSB executable, Alpha (unofficial)": Arch.ALPHA64,
    "ELF 64-bit LSB executable, x86-64": Arch.EXE_86_64,
    "ELF 64-bit LSB shared object, x86-64": Arch.LIB_86_64,
    "ELF 32-bit MSB executable, Motorola m68k": Arch.M68K,
    "ELF 64-bit MSB executable, MIPS": Arch.MIPS64,
    "ELF 32-bit LSB executable, MIPS": Arch.MIPS32_LE,
    "ELF 32-bit MSB executable, MIPS": Arch.MIPS32_BE,
    "ELF 64-bit MSB executable, SPARC V9": Arch.SPARC,
    "ELF 32-bit LSB executable, Renesas SH": Arch.RENESAS,
    "ELF 64-bit LSB executable, ARM aarch64": Arch.ARM64,
    "ELF 32-bit LSB executable, ARM": Arch.ARM32,
    "ELF 64-bit MSB executable, IBM S/390": Arch.S390,
    "ELF 32-bit MSB executable, PA-RISC": Arch.HP_PA,
    "ELF 64-bit LSB executable, UCB RISC-V": Arch.RISCV64,
}


def get_arch(filename):
    out = subprocess.check_output(["file", "-b", filename]).decode()
    if out.startswith("PE32+ executable (console) x86-64"):
        return Arch.PE32
    else:
        arch = ", ".join(out.split(", ")[:2])
        return name_to_arch[arch]


class Family(ABC):
    pass


FILE_LEN = 24315


def file_name(id):
    return f"ncuts/{id}"


def parse_imm(s):
    if s[0] == "#":
        s = s[1:]
    if s[:2] == "0x":
        return int(s[2:], 16)
    return int(s)


def check_answer(qemu, id, num):
    output = subprocess.check_output(f"echo {num} | {qemu} {file_name(id)}", shell=True)
    return b"Congrats!" in output


# with Pool() as p:
#     arch_list = p.map(get_arch, map(file_name, range(FILE_LEN)))

# arch_map = defaultdict(list)
# for (i, arch) in enumerate(arch_list):
#     arch_map[arch].append(i)

context.arch = "aarch64"
context.log_level = "error"

for bin_id in [17892]:
    A = BitVec("A", 32)
    B = BitVec("B", 32)
    s = Solver()
    s.add(A * 132 + B * 25763 == 1480715902)
    s.add(B * 40006 - A * 74713 == 0xA217A13F)
    s.add((A ^ B) == 0xE56C05B3)
    s.add(B == 817563118)
    if s.check() == sat:
        m = s.model()
        w = (m[A].as_long() << 32) | m[B].as_long()
        if check_answer("qemu-aarch64", bin_id, w):
            print(f"{bin_id}: {w}")
        else:
            print(f"{bin_id}: {w} (WRONG!)")
    else:
        print(f"{bin_id}: UNSAT!!")
