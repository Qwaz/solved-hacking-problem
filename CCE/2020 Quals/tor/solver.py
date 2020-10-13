s = "ppr2020{ebggbeebggbeebggbe}"

rotation = ord('c') + 26 - ord('p')
flag = ''

for c in s:
    if 'a' <= c <= 'z':
        flag += chr(ord('a') + ((ord(c) - ord('a')) + rotation) % 26)
    else:
        flag += c

# cce2020{rottorrottorrottor}
print(flag)
