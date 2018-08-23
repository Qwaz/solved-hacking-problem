s1 = 'cat: password: Permission denied\n'
s2 = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+"
assert len(s1) == len(s2)

flag = ''
for (c1, c2) in zip(s1, s2):
    flag += chr(ord(c1) ^ ord(c2))

print flag
