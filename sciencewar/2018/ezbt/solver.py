import binascii

data = '''
D9 51 44 5C 65 D5 3D 7D  C8 67 BC 68 C8 68 6F 3F
C8 64 3F 30 48 41 72 3F  75 C8 67 F4 68 48 B9 6E
7C C8 7F 3C 74 5C 74 3C  74 3C 5C 3C 74 3C 5C 77
48 FE E8 67 C8 49 48 48  48 48 48 48 48 48 48 48
71 43 00 00 00 00 00 00
'''

data = data.replace(' ', '')
data = data.replace('\n', '')
data = list(map(ord, binascii.unhexlify(data)))


def unbit(val, bitsize=8):
    diff = []
    for _ in range(bitsize):
        diff.append(val & 1)
        val = val >> 1

    last = 0
    acc = 0
    for i in range(bitsize - 1, -1, -1):
        now = last ^ diff[i]
        acc = (acc << 1) ^ now
        last = now

    return acc

length = len(data)
for i in range(0, length-8, 8):
    acc = 0
    shift = 0
    for j in range(8):
        acc += data[i+j] << shift
        shift += 8
    acc = unbit(acc, 8 * 8)
    for j in range(8):
        data[i+j] = acc & 0xFF
        acc = acc >> 8

for i in range(length):
    data[i] = unbit(data[i])

print ''.join(map(chr, data))
