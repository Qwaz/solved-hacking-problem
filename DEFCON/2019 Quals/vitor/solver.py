from pwn import *
from z3 import *


def i_to_bytes(i):
    return [BitVecVal((i >> (7 * j)) & 0b1111111, 8) for j in range(4)]

flag = [BitVec('x' + str(i), 8) for i in range(40)]
s = Solver()

for i in range(40):
    s.add(flag[i] >= 0x20)
    s.add(flag[i] < 0x7f)

# step 0
step = [BitVecVal(0, 8) for _ in range(4)]
step_result = i_to_bytes(7061655)

for i in range(10):
    for j in range(4):
        step[j] = step[j] ^ flag[(i * 4) + j]

for i in range(4):
    s.add(step[i] == step_result[i])

# step 1
step = [0 for _ in range(4)]
step_result = i_to_bytes(202429372)

for i in range(0, 10, 2):
    for j in range(4):
        step[j] = step[j] ^ flag[(i + 1) * 4 + j]

for i in range(4):
    s.add(step[i] == step_result[i])

# step 2
step = [0 for _ in range(4)]
step_result = [110, 99, 39, 78]

for i in range(3, 10, 3):
    for j in range(4):
        step[j] = step[j] ^ flag[4 * (i-1) + j]

for i in range(4):
    s.add(step[i] == step_result[i])

# step 3
step = [0 for _ in range(4)]
step_result = [0x42, 0x18, 0x33, 0x13]

for i in range(4):
    step[i] = step[i] ^ flag[12 + i]
for i in range(4):
    step[i] = step[i] ^ flag[28 + i]

for i in range(4):
    s.add(step[i] == step_result[i])

# step 4
step = [0 for _ in range(4)]
step_result = [ord('V'), ord('-'), ord('R'), ord(']')]

for i in range(4):
    step[i] = step[i] ^ flag[0x10 + i]
for i in range(4):
    step[i] = step[i] ^ flag[0x24 + i]

for i in range(4):
    s.add(step[i] == step_result[i])


for i in range(20):
    s.add(flag[20 + i] == ord(" => pHd_1w_e4rL13r;)"[i]))

# Final check!
assert s.check() == sat
m = s.model()

print "OOO{%s}" % ''.join(map(lambda v: chr(m[v].as_long()), flag))
