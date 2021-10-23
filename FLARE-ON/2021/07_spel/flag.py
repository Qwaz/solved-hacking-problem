from binascii import hexlify, unhexlify

# Software/Microsoft/Spell/1
s = bytearray()
b = unhexlify("8A 1D 89 15 14 9F C1 1D  99 7E 8A 1B 00 00 00 00".replace(" ", ""))
for i in range(len(b"flare-on.com")):
    s.append(b[i] ^ b"flare-on.com"[i])
print(hexlify(bytes(s)))

init_buf = unhexlify(
    (
        "E2 A4 B7 A7 D7 AC 87 8D  9B 9C 85 0D D8 8E E5 FA"
        + "C3 C1 A8 06 C2 96 33 00  00 00 00 00 00 00 00 00"
    ).replace(" ", "")
)[:23]

# Software/Microsoft/Spell/0
key = bytearray(
    b"\x80\x97\xc4\x90\x88\xdf\xf7\xbe\xf7\xf0\xe6\x65\xbd\xed\x8e\xc9\xb1\x9e\xcd\x70\xf1\xe4\x73"
)

decrypt_buf = [None for _ in range(22)]

shuffle = (
    8,
    7,
    16,
    9,
    10,
    6,
    5,
    4,
    3,
    -1,
    17,
    19,
    0,
    1,
    20,
    12,
    18,
    11,
    -1,
    14,
    13,
    15,
)

for i in range(22):
    x = shuffle[i]
    if x == -1:
        decrypt_buf[i] = ord("?")
    else:
        decrypt_buf[i] = key[x] ^ init_buf[x]

decrypt_buf = bytes(decrypt_buf)

# Original value found with memory scan
# l3rlcps_7r_vb33eehskc3
print(hexlify(b"l3rlcps_7r_vb33eehskc3"))

flag = bytearray()

flag.append(decrypt_buf[12])
flag.append(decrypt_buf[13])
flag.append(decrypt_buf[6])
flag.append(decrypt_buf[8])
flag.append(decrypt_buf[7])
flag.append(decrypt_buf[6])
flag.append(decrypt_buf[5])
flag.append(decrypt_buf[1])
flag.append(decrypt_buf[0])
flag.append(decrypt_buf[3])
flag.append(decrypt_buf[4])
flag.append(decrypt_buf[17])
flag.append(decrypt_buf[15])
flag.append(decrypt_buf[20])
flag.append(decrypt_buf[19])
flag.append(decrypt_buf[21])
flag.append(decrypt_buf[2])
flag.append(decrypt_buf[10])
flag.append(decrypt_buf[16])
flag.append(decrypt_buf[11])
flag.append(decrypt_buf[14])
flag.append(decrypt_buf[2])
flag.append(0x40)

# b3s7_sp3llcheck3r_ev3r@flare-on.com
print(bytes(flag).decode() + "flare-on.com")
