import subprocess

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

diffs = []
for i in range(LEN - 1):
    for diff in range(256):
        h1 = hash_result(strxor(content, [(i*2, diff), (i*2 + 3, 16)]))
        h2 = hash_result(strxor(content, [(i*2, diff), (i*2 + 1, 16)]))
        print i, diff, h1, h2
        if h1 == h2:
            diffs.append(diff)
            break

print diffs
