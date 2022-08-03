import lzma

with open("extracted/flag.lzma.enc", "rb") as enc:
    enc_data = enc.read()

for key in range(0, 100000):
    start_key = key

    try_data = bytearray(enc_data)
    for i in range(len(try_data)):
        key = (((key >> 3) ^ (key >> 8) ^ (key >> 10) ^ (key >> 15)) & 1 | (2 * key)) & 0xffff
        try_data[i] ^= key & 0xff

    try:
        if try_data[:4] == b"\x5d\x00\x00\x80":
            print(start_key)
            print(try_data)
    except Exception as e:
        pass
