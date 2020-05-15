from functools import reduce

key = "abcdefghijklmnopqrstuvwxyz{}_137"

print(len(key))

pairs = (
    ("RDDDRURRRDLLDLDRRURRDDDR", "clrtffxpry"),
    ("RDDRURDDDRURULURRDDDDDRD", "nyghq7xksg"),
    ("DRDDDDRUURRRULURRDDDDDDR", "ppyyvn}1{7"),
)

maps = {
    "U": '00',
    "R": '01',
    "D": '10',
    "L": '11'
}


def _(x):
    return reduce(lambda x, y: x + (y[1] << y[0]), enumerate(x), 0)


for path, encoded in pairs:
    a = (''.join([bin(key.index(x))[2:].zfill(5) for x in encoded]))
    b = (''.join([maps[x] for x in path]))
    b = b.ljust(len(a), '0')
    print(a)
    print(b)
    l = [int(x) ^ int(y) for x, y in zip(a, b)]
    print(''.join([key[_(l[i:i+5][::-1])] for i in range(0, len(l), 5)]))
