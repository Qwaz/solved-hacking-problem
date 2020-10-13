TYPE_MAP = {
    0: "varint",
    1: "64-bit",
    2: "length-delimited",
    3: "start-group",
    4: "end-group",
    5: "32-bit",
}


def var32(bytes):
    num = 0
    cur = 1
    for byte in bytes:
        num += cur * (byte & 0x7f)
        cur = cur << 7
        if (byte & 0x80) == 0:
            break

    return num


def var32_tag(bytes):
    num = var32(bytes)

    # tag, type
    return (num >> 3, TYPE_MAP[num & 7])


def var32_encode(num):
    b = []
    while True:
        cur = num & 0x7f
        num = num >> 7
        if num != 0:
            cur |= 0x80
        b.append(cur)
        if num == 0:
            break
    return bytes(b)


def assemble(tag, type):
    return var32_encode((tag << 3) | type)
