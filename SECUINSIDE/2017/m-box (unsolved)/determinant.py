import claripy

mem_raw = [claripy.BVS('mem_{}'.format(i), 8) for i in range(81)]

s = claripy.Solver()

for i in range(81):
    s.add(mem_raw[i] > 0x1f)
    s.add(mem_raw[i] <= 0x7e)

check = [53, 117, 110, 75, 110, 48, 119, 110]
s.add(mem_raw[0] == check[0])
for y in range(9):
    for x in range(9):
        if x < 8:
            s.add(mem_raw[y*9 + x] == check[x])

mem = [[mem_raw[y*9 + x].zero_extend(8*7) for x in range(9)] for y in range(9)]


def determinant(lvl, cols):
    if lvl == 8:
        return mem[lvl][cols[0]]
    result = claripy.BVV(0, 8*8)
    for (i, col) in enumerate(cols):
        if i % 2 == 1:
            result -= mem[lvl][col] * determinant(lvl+1, cols[:i]+cols[i+1:])
        else:
            result += mem[lvl][col] * determinant(lvl+1, cols[:i]+cols[i+1:])
    return result

det = determinant(0, [0, 1, 2, 3, 4, 5, 6, 7, 8])

s.add(claripy.Or(det == 1, det == -1))


def int_to_str(num, byte_len):
    return ('%x' % num).zfill(byte_len*2).decode('hex')

result = int_to_str(s.eval(claripy.Concat(*mem_raw), 1), 81)
for i in range(9):
    print ' '.join(map(lambda x: str(ord(x)), result[i*9:(i+1)*9]))
print s.eval(det, 1)
