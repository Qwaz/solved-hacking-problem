from base64 import b64decode
from binascii import hexlify
from os import chmod
from shutil import copyfile
import hashlib
import itertools
import struct
import subprocess
import time

from pwn import *
from unicorn import *
from unicorn.x86_const import *
import angr
import claripy
import pwnlib

con = remote("111.186.58.164", 30212)

print("Solving the hash challenge")

con.recvuntil("sha256(XXXX+")
hash_suffix = con.recvuntil(") == ", drop=True)
hash_result = con.recvline().strip().decode()
con.recvuntil("Give me XXXX:")

found = False

alnum = string.ascii_letters + string.digits
for hash_prefix in itertools.product(alnum, repeat=4):
    hash_prefix = "".join(hash_prefix).encode()
    if hashlib.sha256(hash_prefix + hash_suffix).hexdigest() == hash_result:
        found = True
        log.success(
            "sha256(%s+%s) == %s"
            % (hash_prefix.decode(), hash_suffix.decode(), hash_result)
        )
        con.sendline(hash_prefix)
        break

if not found:
    log.failure("Hash not found...")
    exit(-1)


# by jinmo123
def deobfuscate(code):
    out = bytearray(code)

    def _(x):
        off = struct.unpack("<L", bytes(x))[0]
        if off & 0x80000000:
            off -= 2 ** 32
        return off

    chunk = b"\xe8"
    cur = 0
    while True:
        cur = out.find(chunk, cur + 1)
        if cur != -1:
            if (
                out[cur + 2] == 0
                and out[cur + 3] == 0
                and out[cur + 4] == 0
                and out[cur + 6] == 0xEB
            ):
                out[cur] = 0xE9
                out[cur + 1] = out[cur + 7] + 8 - 5
                continue

            target = cur + 5 + _(out[cur + 1 : cur + 5])
            if 0 <= target < len(out):
                if out[target] == 0xC3:  # nullsub
                    for i in range(5):
                        out[cur + i] = 0x90
                    continue
        else:
            break

    return bytes(out)


# Returns a struct that contains solver configuration
# by jinmo123
def extract(chal_name):
    print("Extracting second stage code")

    data = open(chal_name, "rb").read()
    offset = data[data.find(b"\x48\x63", data.find(b"\xb0\x00\xff") - 0x20) + 4 :][:4]
    offset = struct.unpack("<L", offset)[0]

    # Dynamic analysis (shellcode, memory reading)
    p = subprocess.Popen([chal_name], stdin=subprocess.PIPE)

    time.sleep(3)

    base = f"/proc/{p.pid}/"
    maps = list(open(base + "maps"))
    rwx = [int(line.split("-")[0], 16) for line in maps if "rwx" in line][0]
    rwx_end = [
        int(line.split(" ")[0].split("-")[1], 16) for line in maps if "rwx" in line
    ][0]

    mem = open(base + "mem", "rb")
    mem.seek(rwx)
    code = mem.read(rwx_end - rwx)

    mem.seek(offset)
    offset = struct.unpack("<L", mem.read(4))[0]
    mem.close()

    p.kill()

    return {
        "code": deobfuscate(code),
        "map_to": rwx,
        "offset": offset,
        "map_size": rwx_end - rwx,
    }


# Returns flag
def solve_one(config):
    print("Starting unicorn emulation")

    stack_start = 0x7FFFFFF00000
    stack_top = 0x7FFFFFFFF000
    stack_size = stack_top - stack_start

    map_to = config["map_to"]
    offset = config["offset"]
    map_size = config["map_size"]

    context.arch = "amd64"

    code = config["code"]
    with open("chals/code-debug", "wb") as f:
        f.write(code)

    getLogger("pwnlib.asm").level = "info"

    filename = pwnlib.asm.make_elf(code, vma=map_to, extract=False)

    copyfile(filename, "chals/code-debug.elf")

    call_addrs = []
    goal = None

    # Metadata collection with unicorn
    def code_hook(uc, address, size, user_data):
        nonlocal goal
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

    if goal is None:
        log.failure("Goal not found...")
        exit(-1)

    print("Goal: " + hexlify(goal).decode())

    # angr
    print("Starting angr")

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
            print("Flag: " + hexlify(found_flag).decode())
            return found_flag
        except:
            pass

    log.failure("Flag not found...")
    exit(-1)


for chal in (1, 2, 3):
    print(f"Challenge {chal}")

    con.recvuntil("Here is your challenge:")
    chal_base64 = con.recvuntil("Plz beat me in 10 seconds X3 :)", drop=True).strip()

    chal_name = f"chals/chal{chal}"
    with open(chal_name, "wb") as f:
        f.write(b64decode(chal_base64))

    chmod(chal_name, 0o755)

    config = extract(chal_name)
    flag = solve_one(config)

    con.send(flag)

con.recvuntil("Nice gob. Here is your flag:")
print(con.recvall().strip().decode())
