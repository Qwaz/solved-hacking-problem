import string

for (a, b) in zip("Fpg 8kv xyoi gr bjv dwsnagdl kj: 0l60", "The 8th byte of the password is: 0x60"):
    if a in string.ascii_letters:
        print(a, b, chr(ord("A") + (26 + ord(b) - ord(a)) % 26))
    else:
        print(a, b)
