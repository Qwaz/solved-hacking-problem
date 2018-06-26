import subprocess
import string

LEN = 55

with open('encrypted_secret', 'r') as f:
    content = f.read()


def strxor(s, pairs):
    for (index, val) in pairs:
        s = s[:index] + chr(ord(s[index]) ^ val) + s[index+1:]
    return s


def hash_result(s):
    assert len(s) == LEN * 2
    p = subprocess.Popen("nc dogestore.ctfcompetition.com 1337", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return p.communicate(s)[0]


diffs = [14, 14, 14, 14, 12, 12, 12, 12, 12, 23, 18, 32, 32, 2, 23, 18, 61, 40, 18, 5, 5, 18, 23, 23, 23, 7, 23, 18, 61, 55, 19, 26, 26, 13, 13, 16, 22, 6, 21, 15, 11, 5, 2, 7, 29, 46, 60, 18, 23, 7, 23, 18, 61, 113]
len_diffs = []
for i in range(LEN - 1):
    len_diff = 0
    for len_bit in (1, 2, 4, 8):
        h1 = hash_result(strxor(content, [(i*2, diffs[i]), (i*2 + 3, len_bit)]))
        h2 = hash_result(strxor(content, [(i*2, diffs[i]), (i*2 + 1, len_bit)]))
        print i, len_bit, h1, h2
        if h1 != h2:
            len_diff ^= len_bit
    len_diffs.append(len_diff)

repeats = []

for start in range(256):
    last = start
    len_last = 0
    chars = [chr(start)]
    for (diff, len_diff) in zip(diffs, len_diffs):
        last = last ^ diff
        len_last = len_last ^ len_diff
        chars.append(chr(last) * (len_last + 1))

    joined = ''.join(chars)
    if all(c in string.printable for c in joined):
        print joined
