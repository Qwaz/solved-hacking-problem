from binascii import hexlify

out = [0 for _ in range(24)]

out[0] = 134
out[1] = 72
out[2] = 8
out[3] = 237
out[4] = 30
out[5] = 49
out[6] = 89
out[7] = 229
out[8] = 232
out[9] = 232
out[10] = 228
out[11] = 17
out[12] = 242
out[13] = 81
out[14] = 243
out[15] = 1
out[16] = 225
out[17] = 114
out[18] = 46
out[19] = 224
out[20] = 109
out[21] = 91
out[22] = 103
out[23] = 182

lookup = {}


def rc4(key):
    S = list(range(256))
    j = 0

    ret = []

    # KSA Phase
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA Phase
    i = j = 0
    for _ in range(3):
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ret.append(S[(S[i] + S[j]) % 256])
        i = (i + 1) % 256

    return bytes(ret)


for k0x in range(0x20, 0x7F):
    for k1x in range(0x20, 0x7F):
        key = chr(k0x) + chr(k1x)
        lookup[rc4(key)] = key

print("rc4(CT): " + hexlify(rc4("CT")).decode())
print("rc4(F{): " + hexlify(rc4("F{")).decode())

s = ""
for i in range(8):
    s += lookup[bytes(out[i * 3 : (i + 1) * 3])]

print(s)
