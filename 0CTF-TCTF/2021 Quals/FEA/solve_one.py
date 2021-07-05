from binascii import hexlify

from pwn import *
from unicorn import *
from unicorn.x86_const import *
import angr
import claripy
import pwnlib


stack_start = 0x7FFFFFF00000
stack_top = 0x7FFFFFFFF000
stack_size = stack_top - stack_start


map_to = 0x7FC6E2402000
offset = 0x22096
map_size = 0x100000


context.arch = "amd64"

with open("chals/code-test", "rb") as f:
    code = f.read()

    getLogger("pwnlib.asm").level = "info"
    filename = pwnlib.asm.make_elf(code, vma=map_to, extract=False)
    print(filename)


call_addrs = []
goal = None


# Metadata collection with unicorn
def code_hook(uc, address, size, user_data):
    global goal
    inst = uc.mem_read(address, size)
    if size == 5 and inst[0] == 0xE8:
        # call ...
        inst_disasm = disasm(inst)
        print(f"0x{address:08x}: {inst_disasm}")

        rdi = uc.reg_read(UC_X86_REG_RDI)
        call_addrs.append((address, rdi))
    elif size == 1 and inst[0] == 0xC3:
        # return
        if uc.reg_read(UC_X86_REG_RSP) == stack_top:
            uc.emu_stop()
    elif size == 2 and inst[0] == 0x39 and inst[1] == 0xC2:
        # cmp edx, eax
        inst_disasm = disasm(inst)
        print(f"0x{address:08x}: {inst_disasm}")
        # get argument to the third call
        target_addr = call_addrs[2][1]
        goal = uc.mem_read(target_addr, 8)


def intr_hook(uc, intno, data):
    if intno == 3:
        # sigtrap 0xcc
        t = uc.mem_read(0xDEAD0000, 4)
        t = p32(u32(t) ^ 0xDEADBEEF)
        uc.mem_write(0xDEAD0000, t)
        # print(f"Interrupt 0x{address:08x}")
    else:
        print("Unhandled interrupt %d" % intno)
        uc.emu_stop()


mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(map_to, map_size)
mu.mem_write(map_to, code)

mu.mem_map(stack_start, stack_size)
mu.reg_write(UC_X86_REG_RSP, stack_top)

mu.mem_map(0xDEAD0000, 0x1000)

mu.hook_add(UC_HOOK_CODE, code_hook, begin=map_to + offset, end=map_to + map_size)
mu.hook_add(UC_HOOK_INTR, intr_hook)

mu.emu_start(map_to + offset, -1)


print("Goal: " + hexlify(goal).decode())


# angr
proj = angr.Project(filename)

flag_chars = [claripy.BVS("flag_%d" % i, 8) for i in range(8)]
flag = claripy.Concat(*flag_chars)

entry = proj.factory.entry_state(
    addr=map_to + offset,
    add_options=angr.options.unicorn,
    stdin=flag,
)

sim_mgr = proj.factory.simulation_manager(entry)
# explore until the third call
sim_mgr.explore(find=call_addrs[2][0], num_find=100)


num_sol = len(sim_mgr.found)
for sol_index, found in enumerate(sim_mgr.found):
    print(f"Trying {sol_index+1} of {num_sol} solutions")
    try:
        rsp = found.regs.rsp
        found.solver.add(found.memory.load(rsp + 0x18, 8) == claripy.BVV(goal))

        found_flag = p64(found.solver.eval(flag), endian="big")
        print(hexlify(found_flag).decode())

        break
    except:
        pass
