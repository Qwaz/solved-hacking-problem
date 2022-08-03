from abc import ABC
from collections import defaultdict
from enum import Enum
from multiprocessing import Pool
from capstone import *
from pwn import *
from z3 import *

import archinfo
import angr
import subprocess
import logging


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


with Pool() as p:
    arch_list = p.map(get_arch, map(file_name, range(FILE_LEN)))

arch_map = defaultdict(list)
for (i, arch) in enumerate(arch_list):
    arch_map[arch].append(i)

context.arch = "aarch64"
context.log_level = "error"
logging.getLogger("pwnlib.elf.elf").setLevel("ERROR")

# for bin_id in [64]:
for bin_id in arch_map[Arch.ARM64]:
    e = ELF(file_name(bin_id))
    func_bytes = e.read(0x400540, 400)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    inst_list = list(md.disasm(func_bytes, 0x400540))
    inst_map = {}
    for inst in inst_list:
        inst_map[inst.address] = inst

    # for inst in inst_list:
    #     print("0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))

    if (
        inst_map[0x400580].mnemonic != "mov"
        or inst_map[0x400584].mnemonic != "bl"
        or inst_map[0x400588].mnemonic != "cbnz"
    ):
        continue

    find = parse_imm(inst_map[0x400588].op_str.split(", ")[1])
    avoid = [0x40058c]

    SP_BASE = 0x7F000000

    proj = angr.Project(file_name(bin_id))
    state = proj.factory.blank_state(
        addr=0x400580, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )

    x = state.solver.BVS("x", 64)

    state.memory.store(SP_BASE + 0x20, x)
    state.regs.sp = SP_BASE
    state.regs.x20 = SP_BASE + 0x20

    sm = proj.factory.simulation_manager(state)
    sm.explore(find=find, avoid=avoid)

    s = sm.found[0]
    ans = s.solver.eval(s.memory.load(SP_BASE + 0x20, 8, endness=archinfo.Endness.LE))

    if check_answer("qemu-aarch64", bin_id, ans):
        print(f"{bin_id}: {ans}")
    else:
        print(f"{bin_id}: {ans} (WRONG!)")
