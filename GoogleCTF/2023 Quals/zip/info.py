from pwn import u32

# CRC, as used by ZIP files
# adapted from CRC code in RFC 1952
crc_table = [0] * 256


def make_crc_table():
    for i in range(256):
        c = i
        for j in range(8):
            if (c & 1) != 0:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        crc_table[i] = c


make_crc_table()

# update a crc with just one byte, without pre- and post-conditioning
# for use only with the PKWARE cipher
def update_crc1(crc, b):
    return crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8)


# update a crc given a buffer of bytes
def update_crc(crc, buf):
    crc ^= 0xFFFFFFFF

    for b in buf:
        crc = crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


flag_crc = b"\x9a\xd9\x12\x47"
junk_crc = b"\xbc\x53\x39\x3b"

junk_data = b"\xe2\xf2\xba\x77"

assert update_crc(0, junk_data) == u32(junk_crc)
