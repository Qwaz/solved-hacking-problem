from pwn import *

data = bytes.fromhex('''
a8 3d d0 4f 9b 8d b4 28 5a bd 75 91 49 5c 78 35
ba d8 15 0e 7d bb a1 88 30 38 2b 68 18 a8 28 1c
9d 89 fc 75 0b 58 23 93 62 99 49 e7 be a2 dd dc
94 ad 79 c8 ec 23 0a 85 b6 1f 0e 3f 05 7d 24 31
77 f8 53 91 d7 08 dd 89 2a 5c 43 85 c4 0a 99 60
6b 53 20 33 b6 f7 ee 0e 01 21 2d 40 15 40 84 bd
05 8c f4 c1 c6 7e 85 6d 30 b0 a8 e7 b6 90 1e 45
3f 98 77 32 26 86 d1 2e 8f 75 53 13 a7 f2 8b 77
02 72 ac 61 5f 7d 32 e8 26 6b 66 6c 22 b7 25 25
9c 33 19 24 58 45 96 ce 52 50 c2 dc d6 a1 47 69
63 bf 46 e7 91 4e 24 33 4a 47 04 62 6e c0 a9 56
df 2f d9 02 bc fc 82 cf 88 c4 a4 92 23 4c 55 78
3a 6f de 09 48 42 35 5a a4 4c 91 f5 f1 9b 28 dd
0c a5 ab 0c 89 2a 2b e0 27 b4 7c ab 48 e2 ee 74
7e 22 3f 29 bf 21 41 0c ec bf b7 38 9d fb 41 77
92 11 f0 b8 8d b5 de ba 3d 2e 9a 6e 57 79 7b 5b
1c 07 f8 12 64 95 eb 68 a5 89 33 1f 52 3e bb 7e
28 d7 46 26 8d a4 6a 11 3e 66 7e 5a 5a 80 d7 d8
3a 3a ca 50 3b f8 88 5a 60 6b e4 7b b9 90 54 aa
f9 bf 03 44 20 43 86 b2 83 cf b3 31 64 4b 6b 28
9c f4 d2 5a c0 91 2f 3f d8 6f b3 03 e4 a4 8d f9
15 4b 46 56 09 b6 63 4f 8b 68 4b a5 68 5e 12 af
a7 f9 41 e7 d3 49 3a ee a7 ea 79 72 12 40 de d4
2e 0f 9d 4b 1d 49 cb 6f a7 3a 02 c7 0f 57 9f be
2c 8c 06 da 06 1e 89 e4 6b 9b 2b 90 01 d8 c2 d1
ea 5c 34 40 1b 58 42 19 b2 a1 e7 fc 1f 76 de 3c
d2 17 be 86 c0 6a 43 8e 05 76 39 ac 77 2e e6 69
d6 61 40 35 c4 c7 94 a3 38 0b 44 7d eb 1f 6d 75
63 2d e4 42 42 e4 2d 63 bc 11 b5 ee dc 0e 08 db
7e 45 41 e0 d1 9a ad a8 11 f7 d8 aa 95 d8 a9 53
0e 00 a4 da 18 90 03 2c be d5 29 23 77 02 12 0f
dd c5 a3 48 52 a6 7f 16 d3 54 6e b6 ff 98 6c 28
db 42 25 6a a7 cb 69 69 c5 ea c3 a2 2e 6f 7a 30
63 e8 be 17 1b b9 19 03 9b a3 07 b6 6e 0d 7a 66
''')[:0x200]
answer = xor(data[:0x200], b'a'*512)

def vadd(a, b):
    return bytes(x + y & 0xff for x, y in zip(a, b))

def vxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rol32(x, k):
    x &= 0xffffffff
    k &= 31
    return (x << k | x >> (32 - k)) & 0xffffffff

def ror32(x, k):
    x &= 0xffffffff
    k &= 31
    return (x >> k | x << (32 - k)) & 0xffffffff

def bswap64(x):
    return int.from_bytes(x.to_bytes(8, 'little'), 'big')

class ViperCipher:
    def __init__(self, challenge, encrypt):
        self.challenge = challenge
        self.encrypt = encrypt

        self.index = 0
        if not self.encrypt:
            self.ADD_CONSTANT = bytes.fromhex('05 6a cf 34 99 fe 63 c8 2d 92 f7 5c c1 26 8b f0')
            self.rot_base = 5
            self.rot_consts = [5, 12, 9, 4]
        else:
            self.ADD_CONSTANT = bytes.fromhex('11 76 db 40 a5 0a 6f d4 39 9e 03 68 cd 32 97 fc')
            self.rot_base = 17
            self.rot_consts = [32-15, 32-8, 32-3, 32-8]

        self.XOR_CONSTANT = bytes.fromhex('00 15 2a 3f 54 69 7e 93 a8 bd d2 e7 01 16 2b 40')

        self.key_schedule()

    def key_schedule(self):
        self.state = bytes(challenge)
        self.state = vadd(self.state, self.ADD_CONSTANT)
        self.state = vxor(self.state, self.XOR_CONSTANT)
        self.state = bytes((self.state[i & 0xf] + i) & 0xff for i in range(256))
        self.state = [int.from_bytes(self.state[i*8:(i+1)*8], 'little') for i in range(32)]

        for i in range(0x1400):
            i1 = (i + 0) & 0x1f
            i2 = (i + 4) & 0x1f
            i3 = (i + 9) & 0x1f
            i4 = (i + 16) & 0x1f

            p1 = self.state[i1]
            p2 = self.state[i2]
            p3 = self.state[i3]
            p4 = self.state[i4]

            p1 = (ror32(p1, self.rot_consts[0]) ^ p2) + 0x4141414142424242 & 0xffffffffffffffff
            p2 = (ror32(p2, self.rot_consts[1]) ^ p3) + 0x6666666677777777 & 0xffffffffffffffff
            p3 = (rol32(p3, self.rot_consts[2]) ^ bswap64(p4)) + 0x4444444455555555 & 0xffffffffffffffff
            p4 = (rol32(p4, self.rot_consts[3]) ^ p1) - 0x7f7f7f7f6f6f6f70 & 0xffffffffffffffff
            p4 = (p4 + bswap64(p1)) & 0xffffffffffffffff

            self.state[i1] = p1
            self.state[i2] = p2
            self.state[i3] = p3
            self.state[i4] = p4

    def update_state(self):
        uconst0 = self.state[19]
        uconst1 = self.state[29]
        uconst2 = self.state[8]
        uconst3 = self.state[1]

        z = 0x10
        for i in range(0x100):
            i1 = (i + 0) & 0x1f
            i2 = (i + 4) & 0x1f
            i3 = (i + 9) & 0x1f
            i4 = (i + 16) & 0x1f
            i4 = z & 0x1f

            p1 = self.state[i1]
            p2 = self.state[i2]
            p3 = self.state[i3]
            p4 = self.state[i4]

            # different for each direction
            r1 = self.rot_base + 0
            r2 = self.rot_base + 7
            r3 = self.rot_base + 0x12
            r4 = self.rot_base + 0x17

            p1 = (ror32(p1 + uconst3, r1) ^ p2) + uconst0 & 0xffffffffffffffff
            p2 = (ror32(p2 + uconst2, r2) ^ p3) + uconst1 & 0xffffffffffffffff
            p3 = (ror32(p3 + uconst1, r3) ^ bswap64(p4)) + uconst2 & 0xffffffffffffffff
            tmp = (ror32(p4 + uconst0, r4) ^ p1) + uconst3 & 0xffffffffffffffff
            p4 = ~(tmp + bswap64(p1)) & 0xffffffffffffffff
            z += 0x1f

            if i < 10:
                print(i1, i2, i3, i4, z & 0x1f)
                print(*map(hex, [p1, p2, p3, p4]))

            self.state[i1] = p1
            self.state[i2] = p2
            self.state[i3] = p3
            self.state[i4] = p4

    def crypt(self, data: bytes) -> bytes:
        result = bytearray(len(data))
        s_bytes = b''.join(s.to_bytes(8, 'little') for s in self.state)

        for i in range(len(data)):
            if self.index == 0x100:
                self.update_state()
                s_bytes = b''.join(s.to_bytes(8, 'little') for s in self.state)
                self.index = 0

            result[i] = data[i] ^ s_bytes[self.index]
            self.index = self.index + 1

        return bytes(result)

challenge = bytes.fromhex('05460b6868e32690c28588ace5da56b4')

enc_cipher = ViperCipher(challenge, encrypt=True)
dec_cipher = ViperCipher(challenge, encrypt=False)

# print(dec_cipher.crypt(b'a'*512).hex(' '))
print(enc_cipher.crypt(b'a'*512).hex(' '))
print()
print(data.hex(' '))
