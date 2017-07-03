import angr
import claripy

from ctypes import *
import os

libc = CDLL('libc.so.6')

libc.srand(c_int(60516051))
rand_values = [libc.rand() for i in range(81)]


def get_rand_value(idx):
    return rand_values[idx]

# Initial state setting
b = angr.Project('m-box', load_options={'auto_load_libs': False})

vec = claripy.BVS('input', 8*81)
start = b.factory.blank_state(addr=0x400a3f)
start.memory.store(0x603c60, vec)


# Hook rand call
def srand(state):
    state.memory.store(0xcafebabe, claripy.BVV(0, 8*1))

b.hook(0x400b0a, srand, length=5)


def rand(state):
    cnt = state.se.any_int(state.memory.load(0xcafebabe, 1))
    state.memory.store(0xcafebabe, claripy.BVV(cnt+1, 8*1))
    state.regs.rax = claripy.BVV(get_rand_value(cnt), 8*8)

b.hook(0x400b2a, rand, length=5)


# Symbolic execution
pg = b.factory.path_group(start)
pg.explore(
    find=0x4014ab,
    avoid=[
        0x400a5e,
        0x401407,
        0x401497,
    ]
)

print '[+] Path Found'

original_state = pg.found[0].state

mem = [[original_state.memory.load(0x603c60 + y*9 + x, 1) for x in range(9)] for y in range(9)]


def reverse_answer(s):
    tmp_state = original_state.copy()
    requirement = map(int, s.strip().split())

    for y in range(9):
        for x in range(9):
            tmp_state.add_constraints(mem[y][x] == requirement[y*9 + x])

    wanted = tmp_state.se.any_str(vec).encode('hex')
    print wanted
    os.system("unhex '{}' | ./m-box".format(wanted))
