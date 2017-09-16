def ck(index, c1, c2):
    mod = index % 6
    if mod == 0:
        r = ((c1 & 0xFFF0) >> 4) ^ c2
    elif mod == 1:
        r = ((c1 & 0xFFE0) >> 5) ^ c2
    elif mod == 2:
        r = ((c1 & 0xFF80) >> 7) ^ c2
    elif mod == 3:
        r = ((c1 & 0xFFC0) >> 6) ^ c2
    elif mod == 4:
        r = c2
    elif mod == 5:
        r = c2 ^ 0xF
    else:
        r = 67
    return chr(r)

s = 'XT=S=_=^="= =!=\''
s_decode = ''

for c in s:
    s_decode += chr(ord(c) ^ 0x10)

print(s_decode)

p = 'SBtbhfle_7tg]Runsj5]io_MBmi'

print(len(p))

flag = ''

for i in range(len(p)):
    if i < 16:
        flag += ck(i, ord(s_decode[i]), ord(p[i]))
    else:
        flag += ck(i, ord(s_decode[i-16]), ord(p[i]))

print(flag)
