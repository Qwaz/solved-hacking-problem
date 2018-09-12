from base64 import b64decode, b64encode
from Crypto.Util.number import long_to_bytes


def decode(s):
    i = 0

    out = ''
    while True:
        out_byte = ord(s[i]) - 32
        i += 1
        for _ in range(0, out_byte, 3):
            acc = 0
            acc = (acc << 6) + ord(s[i]) - 32
            i += 1
            acc = (acc << 6) + ord(s[i]) - 32
            i += 1
            acc = (acc << 6) + ord(s[i]) - 32
            i += 1
            acc = (acc << 6) + ord(s[i]) - 32
            i += 1
            out += long_to_bytes(acc)
        if out_byte != 45:
            break

    return out


def reverse_map(c):
    if 'a' <= c <= 'z':
        return chr(ord('a') + (ord(c) - ord('a') - 13) % 26)
    if 'A' <= c <= 'Z':
        return chr(ord('A') + (ord(c) - ord('A') - 13) % 26)
    return c

s = '@25-Q44E233=,>E-M34=,,$LS5VEQ45)M2S-),7-$/3T '

new_s = ''.join(map(reverse_map, decode(s)))
print b64decode(new_s)
