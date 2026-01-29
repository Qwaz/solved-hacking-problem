from pwn import *


data_406040 = b"\x05j\xcf4\x99\xfec\xc8-\x92\xf7\\\xc1&\x8bh"
data_406050 = b"\x00\x15*?Ti~\x93\xa8\xbd\xd2\xe7\x01\x16+@"
data_406060 = b"\x11v\xdb@\xa5\no\xd49\x9e\x03h\xcd2\x97\xfc"


# This is used when the server sends data to us
class Decryption:
    def __init__(self, init_bytes: bytes):
        assert len(init_bytes) == 16

        self.idx: int = 0
        self.table: bytearray = bytearray([0] * 256)

        temp = bytearray([0] * 16)
        for i in range(16):
            temp[i] = (data_406040[i] + init_bytes[i]) & 0xFF
            temp[i] ^= data_406050[i]

        for i in range(256):
            self.table[i] = (temp[i % 16] + i) & 0xFF

        # Mixing loop - runs 5120 iterations
        for i in range(5120):
            # The table is treated as 32 qwords (8-byte chunks)
            # Indices are calculated as (value & 0x1f) * 8 to get byte offset

            idx0 = ((i) & 0x1F) * 8
            idx1 = ((i + 4) & 0x1F) * 8
            idx2 = ((i + 9) & 0x1F) * 8
            idx3 = ((i + 0x10) & 0x1F) * 8

            # Read 8-byte values from table
            val0 = u64(self.table[idx0 : idx0 + 8])
            val1 = u64(self.table[idx1 : idx1 + 8])
            val2 = u64(self.table[idx2 : idx2 + 8])
            val3 = u64(self.table[idx3 : idx3 + 8])

            # First operation on idx0
            val0 = ((rol(val0, 0xf, 32) & 0xFFFFFFFF) ^ val1) + 0x4141414142424242
            val0 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx0 : idx0 + 8] = p64(val0)

            # Second operation on idx1
            val1 = ((rol(val1, 8, 32) & 0xFFFFFFFF) ^ val2) + 0x6666666677777777
            val1 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx1 : idx1 + 8] = p64(val1)

            # Third operation on idx2
            val2 = (
                (ror(val2, 3, 32) & 0xFFFFFFFF) ^ u64(p64(val3)[::-1])
            ) + 0x4444444455555555
            val2 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx2 : idx2 + 8] = p64(val2)

            # Fourth operation on idx3
            val0_new = u64(self.table[idx0 : idx0 + 8])  # Re-read after update
            val3 = ((ror(val3, 8, 32) & 0xFFFFFFFF) ^ val0_new) - 0x7F7F7F7F6F6F6F70
            val3 &= 0xFFFFFFFFFFFFFFFF
            val3 = (val3 + u64(p64(val0_new)[::-1])) & 0xFFFFFFFFFFFFFFFF
            self.table[idx3 : idx3 + 8] = p64(val3)

    def update_table(self):
        const_0x98 = u64(self.table[0x98 : 0x98 + 8])
        const_0xe8 = u64(self.table[0xE8 : 0xE8 + 8])
        const_0x40 = u64(self.table[0x40 : 0x40 + 8])
        const_0x08 = u64(self.table[0x08 : 0x08 + 8])

        r10 = 0x10
        rot = 0x11  # 4082a2

        for j in range(0x100):
            idx0 = (j & 0x1F) * 8
            idx1 = ((j + 4) & 0x1F) * 8
            idx2 = ((j + 9) & 0x1F) * 8
            idx3 = (r10 & 0x1F) * 8

            val0 = u64(self.table[idx0 : idx0 + 8])
            val1 = u64(self.table[idx1 : idx1 + 8])
            val2 = u64(self.table[idx2 : idx2 + 8])
            val3 = u64(self.table[idx3 : idx3 + 8])

            val0 = ((ror(val0 + const_0x08, rot, 32) & 0xFFFFFFFF) ^ val1) + const_0x98
            val0 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx0 : idx0 + 8] = p64(val0)

            val1 = (
                (ror(val1 + const_0x40, (rot + 7) & 0x1F, 32) & 0xFFFFFFFF) ^ val2
            ) + const_0xe8
            val1 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx1 : idx1 + 8] = p64(val1)

            val2 = (
                (ror(val2 + const_0xe8, (rot + 0x12) & 0x1F, 32) & 0xFFFFFFFF)
                ^ u64(p64(val3)[::-1])
            ) + const_0x40
            val2 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx2 : idx2 + 8] = p64(val2)

            val0_new = u64(self.table[idx0 : idx0 + 8])
            val3 = (
                (ror(val3 + const_0x98, (rot + 0x17) & 0x1F, 32) & 0xFFFFFFFF)
                ^ val0_new
            ) + const_0x08
            val3 &= 0xFFFFFFFFFFFFFFFF
            val3 = (~(val3 + u64(p64(val0_new)[::-1]))) & 0xFFFFFFFFFFFFFFFF
            self.table[idx3 : idx3 + 8] = p64(val3)

            r10 += 0x1F

    def decrypt(self, buf: bytes) -> bytes:
        ret = b""

        for b in buf:
            if self.idx == 256:
                self.update_table()
                self.idx = 0

            ret += bytes([self.table[self.idx] ^ b])
            self.idx += 1

        return ret


# This is used when the server reads data from us
class Encryption:
    def __init__(self, init_bytes: bytes):
        assert len(init_bytes) == 16

        self.idx: int = 0
        self.table: bytearray = bytearray([0] * 256)

        temp = bytearray([0] * 16)
        for i in range(16):
            temp[i] = (data_406060[i] + init_bytes[i]) & 0xFF
            temp[i] ^= data_406050[i]

        for i in range(256):
            self.table[i] = (temp[i % 16] + i) & 0xFF

        # Mixing loop for first table - runs 5120 iterations
        for i in range(5120):
            idx0 = ((i) & 0x1F) * 8
            idx1 = ((i + 4) & 0x1F) * 8
            idx2 = ((i + 9) & 0x1F) * 8
            idx3 = ((i + 0x10) & 0x1F) * 8

            val0 = u64(self.table[idx0 : idx0 + 8])
            val1 = u64(self.table[idx1 : idx1 + 8])
            val2 = u64(self.table[idx2 : idx2 + 8])
            val3 = u64(self.table[idx3 : idx3 + 8])

            val0 = ((ror(val0, 5, 32) & 0xFFFFFFFF) ^ val1) + 0x4141414142424242
            val0 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx0 : idx0 + 8] = p64(val0)

            val1 = ((ror(val1, 0xC, 32) & 0xFFFFFFFF) ^ val2) + 0x6666666677777777
            val1 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx1 : idx1 + 8] = p64(val1)

            val2 = (
                (rol(val2, 9, 32) & 0xFFFFFFFF) ^ u64(p64(val3)[::-1])
            ) + 0x4444444455555555
            val2 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx2 : idx2 + 8] = p64(val2)

            val0_new = u64(self.table[idx0 : idx0 + 8])
            val3 = ((rol(val3, 4, 32) & 0xFFFFFFFF) ^ val0_new) - 0x7F7F7F7F6F6F6F70
            val3 &= 0xFFFFFFFFFFFFFFFF
            val3 = (val3 + u64(p64(val0_new)[::-1])) & 0xFFFFFFFFFFFFFFFF
            self.table[idx3 : idx3 + 8] = p64(val3)

    def update_table(self):
        const_0x98 = u64(self.table[0x98 : 0x98 + 8])
        const_0xe8 = u64(self.table[0xE8 : 0xE8 + 8])
        const_0x40 = u64(self.table[0x40 : 0x40 + 8])
        const_0x08 = u64(self.table[0x08 : 0x08 + 8])

        r10 = 0x10
        rot = 5  # 408182

        for j in range(0x100):
            idx0 = (j & 0x1F) * 8
            idx1 = ((j + 4) & 0x1F) * 8
            idx2 = ((j + 9) & 0x1F) * 8
            idx3 = (r10 & 0x1F) * 8

            val0 = u64(self.table[idx0 : idx0 + 8])
            val1 = u64(self.table[idx1 : idx1 + 8])
            val2 = u64(self.table[idx2 : idx2 + 8])
            val3 = u64(self.table[idx3 : idx3 + 8])

            val0 = ((ror(val0 + const_0x08, rot, 32) & 0xFFFFFFFF) ^ val1) + const_0x98
            val0 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx0 : idx0 + 8] = p64(val0)

            val1 = (
                (ror(val1 + const_0x40, (rot + 7) & 0x1F, 32) & 0xFFFFFFFF) ^ val2
            ) + const_0xe8
            val1 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx1 : idx1 + 8] = p64(val1)

            val2 = (
                (ror(val2 + const_0xe8, (rot + 0x12) & 0x1F, 32) & 0xFFFFFFFF)
                ^ u64(p64(val3)[::-1])
            ) + const_0x40
            val2 &= 0xFFFFFFFFFFFFFFFF
            self.table[idx2 : idx2 + 8] = p64(val2)

            val0_new = u64(self.table[idx0 : idx0 + 8])
            val3 = (
                (ror(val3 + const_0x98, (rot + 0x17) & 0x1F, 32) & 0xFFFFFFFF)
                ^ val0_new
            ) + const_0x08
            val3 &= 0xFFFFFFFFFFFFFFFF
            val3 = (~(val3 + u64(p64(val0_new)[::-1]))) & 0xFFFFFFFFFFFFFFFF
            self.table[idx3 : idx3 + 8] = p64(val3)

            r10 += 0x1F

    def encrypt(self, buf: bytes) -> bytes:
        ret = b""

        for b in buf:
            if self.idx == 256:
                self.update_table()
                self.idx = 0

            ret += bytes([self.table[self.idx] ^ b])
            self.idx += 1

        return ret


con = remote("localhost", 9999)

init_bytes = con.recvn(16)
