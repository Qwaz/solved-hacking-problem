from win32_names import NAME

def rotr32(x, n):
    return (x >> n) + ((x << (32 - n))) & 0xFFFFFFFF


def rotl32(x, n):
    return rotr32(x, 32 - n)


def rotr_hash(s):
    if isinstance(s, str):
        s = s.encode()

    val = 0
    for c in s:
        val = (val + c) & 0xFFFFFFFF
        val = rotr32(val, 13)

    return val


def rotl_hash(s):
    if isinstance(s, str):
        s = s.encode()

    val = 0
    for c in s:
        val = c ^ rotl32(val, 7)

    return val


def lookup_rotl(hash):
    for name in NAME:
        if rotl_hash(name) == hash:
            print("Found: " + name)
            return
    print("Not Found")
