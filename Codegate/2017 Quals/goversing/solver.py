import binascii


id = [07, 00, 04, 05, 04, 07, 07, 00, 04, 02, 00, 06, 06, 03, 04, 05, 04, 00, 03, 06, 01, 00, 06, 01, 07, 02, 00, 06, 01, 07, 05, 03, 04, 02, 00, 06, 01, 00, 01, 05, 06, 03, 04, 05, 04, 07, 07, 07, 07, 00, 04, 05, 04, 00, 03, 01, 05, 06, 03, 03, 06, 06, 04, 07]
pw = [0x12, 0x56, 0x2E, 0x1B, 0x5C, 0x34, 0x6A, 0x5D, 0x73, 0x29, 0x0F, 0x5B, 0x1C, 0x67, 0x34, 0x6F, 0x11, 0x50, 0x1E, 0x3A, 0x19, 0x70, 0x35, 0x54, 0x3F, 0x45, 0x2D, 0x47, 0x2E]

id_bits = ''
p0, p1, p2 = 0, 0, 0

for t in id:
    want4 = t >> 2
    want2 = (t >> 1) & 1
    want1 = t & 1

    bit = want4 ^ 1
    assert bit == (want2 ^ p0 ^ p1 ^ p2 ^ 1)
    assert bit == (want1 ^ p0 ^ p2 ^ 1)

    id_bits += str(bit)
    p0, p1, p2 = bit, p0, p1

id_str = binascii.unhexlify('%x' % int(id_bits, 2))
print '[+] ID: ' + id_str  # Admin@G0

pw_str = ''

for i, t in enumerate(pw):
    c = chr(ord(id_str[i % len(id_str)]) ^ t)
    pw_str += c

print '[+] PW: ' + pw_str  # S2Cr2t-m2Mb2r's_P4sSw0rd~!@.@
