def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    return out


def get_string_at(addr):
    return get_string(addr - 0x12040 + 0x001fb5a0)


def get_i32_at(addr):
    addr = addr - 0x12040 + 0x001fb5a0
    return Byte(addr) | (Byte(addr + 1) << 8) | (Byte(addr + 2) << 16) | (Byte(addr + 3) << 24)


def define_struct(name, sz):
    sid = add_struc(-1, name, 0)
    for offset in xrange(0, sz, 4):
        add_struc_member(sid, "field_%X" % offset, -1, FF_DWORD, -1, 4)
