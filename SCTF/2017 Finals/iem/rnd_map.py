import pickle
import random
import os.path


def genRndMap(seed=None, size=4096):
    if seed:
        random.seed(seed)
    return [random.randint(0, 0xfff) for _ in range(size)]


def permutation(m):
    l, r = m & 0xfff, m >> 12
    for i in range(8):
        l, r = r, rndMap[r] ^ l
    return r | (l << 12)

rndMap = genRndMap('I love Crypto. How about you?')

with open('rnd_map', 'w') as f:
    for i in range(0x1000):
        f.write('%d: %d\n' % (i, rndMap[i]))
