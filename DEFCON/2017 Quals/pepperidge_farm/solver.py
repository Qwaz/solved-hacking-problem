from z3 import *

a = [BitVec('X'+str(i), 16) for i in range(32)]

s = Solver()

for i in range(32):
    s.add((a[i] & 0xFF00) == 0)


def arr(idx):
    return a[idx]*256 + a[idx+1]


def zero_check(xor, target):
    s.add((xor ^ target) & 0xFFFF == 0)


zero_check(
    0x7CF5,
    (arr(0) ^ 0x4936) + arr(0x14)
)

zero_check(
    0x3DD8,
    (arr(2) ^ 0x0FDF) * arr(6) * arr(8)
)

zero_check(
    0xEB70,
    (arr(4) ^ 0xC7DF) + (arr(0xE) * arr(0xC))
)

zero_check(
    0x500D,
    (arr(6) ^ 0xC5DB) + 0x14AA
)

zero_check(
    0x7BE8,
    arr(8) * arr(0x1E)
)

zero_check(
    0xDF28,
    arr(0xA) + arr(6) + arr(0xC)
)

zero_check(
    0x3B78,
    0x3008 | (arr(0xC) + 0x5432)
)

zero_check(
    0x1697,
    arr(0xE) + 0x1212
)

zero_check(
    0x3136,
    arr(0x10) ^ 0x8703
)

zero_check(
    0x6272,
    arr(0x12) + 0x4004 + (arr(0x14) ^ 0x0A52)
)

'''
zero_check(
    0x0A52,
    arr(0x14)
)
'''

zero_check(
    0x9308,
    arr(0x16) + arr(0x10)
)

zero_check(
    0x085B,
    arr(0x18)
)

zero_check(
    0x9113,
    (arr(0x1A) ^ 0x863C) + 0x1234
)

zero_check(
    0xF0B8,
    arr(0x1C) + arr(0x8) + arr(0x12)
)

zero_check(
    0x9F94,
    (arr(0x1E) & 0x0F00) + arr(0)
)


s.check()
m = s.model()

ans = ''
for i in range(32):
    ans += '%02X' % int(m[a[i]].as_long())

print ans
