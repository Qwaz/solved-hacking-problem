from z3 import *

target = [
    0x3636fe72, 0x8c95609c, 0xc8d19080, 0xf4da2d9d,
    0x1148add2, 0x15e46b61, 0xdfbcb5a0, 0x4ca1ac10,
    0xc92955bb, 0xe995b2a9, 0x27a0b6f6, 0x88b8b5ef,
    0x8c2e2ff5, 0x04c7a448, 0xa692e761, 0x7ade2f39,
    0xa7ff2cba, 0x970c382f, 0xb11f4770, 0x6e835e3c,
    0xdc240999, 0x83ffe36d, 0xb6ed92e5, 0x7ccbd93b,
    0x8e1311d4, 0x65e44a4f, 0x10f7a401, 0xb51c1bb8,
    0x036b7c84, 0xedea4047, 0xa25caf85, 0x0d7b1134,
    0x964a9720, 0x9bdccacf, 0xc5922ddc, 0x00000000,
]

U64_MASK = (1 << 64) - 1
U32_MASK = (1 << 32) - 1
U16_MASK = (1 << 16) - 1
U8_MASK = (1 << 8) - 1


def step(table):
    if table[624] > 623:
        for i in range(227):
            if table[i+1] & 1:
                t = 0x9908B0DF
            else:
                t = 0
            table[i] = t ^ table[i+397] ^ ((table[i] & 0xFFFFFFFF80000000 | table[i+1] & 0x7FFFFFFF) >> 1)
        for i in range(227, 623):
            if table[i+1] & 1:
                t = 0x9908B0DF
            else:
                t = 0
            table[i] = t ^ table[i-227] ^ ((table[i] & 0xFFFFFFFF80000000 | table[i+1] & 0x7FFFFFFF) >> 1)
        if table[0] & 1:
            t = 0x9908B0DF
        else:
            t = 0
        table[623] = t ^ table[396] ^ ((table[623] & 0xFFFFFFFF80000000 | table[0] & 0x7FFFFFFF) >> 1)
        table[624] = 0

    idx = table[624]
    table[624] += 1

    v1 = (table[idx] >> 11) ^ table[idx]
    v2 = (v1 << 7) & 0x9D2C5680
    v3 = ((v2 ^ v1) << 15) & 0xEFC60000 ^ (v2 ^ v1)
    return (v3 >> 18) ^ v3


FLAG_LEN = 35

flag = BitVec('flag', 8 * FLAG_LEN)


def get_ith(i, FLAG_LEN):
    return ZeroExt(24, Extract(FLAG_LEN*8-1 - i*8, FLAG_LEN*8-8 - i*8, flag))

s = Solver()

for i in range(FLAG_LEN):
    v = Extract(i*8+7, i*8, flag)
    s.add(And(0x20 <= v, v < 0x7f))

table = [0 for i in range(625)]

table[0] = 0x60516051
for i in range(1, 624):
    v1 = (0x6c078965 * ((table[i-1] >> 30) ^ table[i-1])) & U64_MASK
    v2 = i - 624 * ((0xd20d20d20d20d21 * (i >> 4) >> 64) >> 1)
    table[i] = (v1 + v2) & U32_MASK
table[624] = 624

vec = []

for i in range(FLAG_LEN):
    a = step(table)
    b = step(table) & 0xFFFFFF ^ a
    c = (step(table) & U16_MASK) ^ b
    d = (step(table) & U8_MASK) ^ c
    # flag chars are printable, so sign extension can be ignored
    e = get_ith(i, FLAG_LEN) ^ d
    vec.append(e ^ U32_MASK)

for j in range(FLAG_LEN):
    for k in range(FLAG_LEN):
        vec[k] = (LShR(vec[k], 16) | (vec[k] << 16)) & U32_MASK

    for l in range(FLAG_LEN-1):
        prev = vec[l]
        now = vec[l+1]
        for m in range(32):
            now ^= (prev & (1 << m)) << (31 - m)
        vec[l+1] = now

    for n in range(FLAG_LEN-1):
        vec[n], vec[n+1] = vec[n+1], vec[n]

for i in range(FLAG_LEN):
    s.add(vec[i] == target[FLAG_LEN-1-i])

if s.check() == sat:
    m = s.model()
    print (('%0'+str(FLAG_LEN*2)+'x') % m[flag].as_long()).decode('hex')
else:
    print 'Flag length %d failed...' % FLAG_LEN
