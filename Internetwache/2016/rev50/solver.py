target = 'IVyN5U3X)ZUMYCs'

t = 0
r = ''
for c in target:
    r += chr(ord(c) ^ t)
    t += 1

print(r)
