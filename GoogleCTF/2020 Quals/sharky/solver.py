#! /usr/bin/env python
from binascii import hexlify, unhexlify
import struct
import sha256

from pwn import *

MSG = b'Encoded with random keys'


initial_state = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
]

round_consts = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def wrap(num):
    return num & 0xffffffff


def rotate_right(v, n):
    w = (v >> n) | (v << (32 - n))
    return wrap(w)


# Only support one-block size message for simplicity
# https://en.wikipedia.org/wiki/SHA-2#Pseudocode
class ReversibleSha256:
    def __init__(self, msg):
        self.msg = msg
        self.msg_padded = self.padding(msg)
        assert len(self.msg_padded) == 64

        self.state = initial_state[:]
        self.w = self.compute_w(self.msg_padded)
        self.round = 0


    def padding(self, m):
        lm = len(m)
        lpad = struct.pack('>Q', 8 * lm)
        lenz = -(lm + 9) % 64
        return m + bytes([0x80]) + bytes(lenz) + lpad


    def compute_w(self, m):
        w = list(struct.unpack('>16L', m))
        for _ in range(16, 64):
            a, b = w[-15], w[-2]
            s0 = rotate_right(a, 7) ^ rotate_right(a, 18) ^ (a >> 3)
            s1 = rotate_right(b, 17) ^ rotate_right(b, 19) ^ (b >> 10)
            s = wrap(w[-16] + w[-7] + s0 + s1)
            w.append(s)
        return w


    def finalize(self):
        assert self.round == 64
        return struct.pack('>8L', *[wrap(x + y) for x, y in zip(self.state, initial_state)])


    def forward(self):
        a, b, c, d, e, f, g, h = self.state
        s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
        ch = (e & f) ^ (~e & g)
        tmp1 = wrap(h + s1 + ch + round_consts[self.round] + self.w[self.round])
        s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        tmp2 = wrap(s0 + maj)

        self.state = (wrap(tmp1 + tmp2), a, b, c, wrap(d + tmp1), e, f, g)
        self.round += 1


    def backward(self):
        self.round -= 1
        (tmp1_tmp2, a, b, c, d_tmp1, e, f, g) = self.state
        
        s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
        ch = (e & f) ^ (~e & g)
        tmp1_minus_h = wrap(s1 + ch + round_consts[self.round] + self.w[self.round])
        s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        tmp2 = wrap(s0 + maj)

        h = wrap(tmp1_tmp2 - tmp1_minus_h - tmp2)
        tmp1 = wrap(tmp1_minus_h + h)
        d = wrap(d_tmp1 - tmp1)

        self.state = (a, b, c, d, e, f, g, h)

    # Calculate expected A value 7 rounds ago
    # Based on Equation 8 from
    # https://link.springer.com/content/pdf/10.1007/978-3-642-10366-7_34.pdf
    def expected_a(self):
        def calc_d(a, b, c, d, e):
            s0 = rotate_right(b, 2) ^ rotate_right(b, 13) ^ rotate_right(b, 22)
            maj = (b & c) ^ (b & d) ^ (c & d)
            return wrap(e - a + (s0 + maj))

        # N
        a, b, c, d, e, f, g, h = self.state

        # N-1
        prev_d = calc_d(a, b, c, d, e)
        a, b, c, d, e, f, g = b, c, d, prev_d, f, g, h

        # N-2
        prev_d = calc_d(a, b, c, d, e)
        a, b, c, d, e, f = b, c, d, prev_d, f, g

        # N-3
        prev_d = calc_d(a, b, c, d, e)
        a, b, c, d, e = b, c, d, prev_d, f

        # N-4
        prev_d = calc_d(a, b, c, d, e)
        a, b, c, d = b, c, d, prev_d

        # N-5
        a, b, c = b, c, d

        # N-6
        a, b = b, c

        # N-7
        a = b

        return a


con = remote("sharky.2020.ctfcompetition.com", 1337)

con.recvuntil("MSG Digest: ")
target_hex = con.recvline().strip()
print("Target: " + target_hex.decode())

target_state = struct.unpack(">8L", unhexlify(target_hex))

# Overwrite the state
front = ReversibleSha256(MSG)
back = ReversibleSha256(MSG)
back.state = [wrap(x - y) for x, y in zip(target_state, initial_state)]
back.round = 64

for _ in range(56):
    back.backward()

assert front.round == 0
assert back.round == 8

for idx in range(8):
    expected_a = back.expected_a()

    # Go back and forth to recover the correct value for K_i
    front.forward()
    found_key = wrap((expected_a - front.state[0]) + round_consts[idx])
    front.backward()

    # Actually fix the round constant table and proceed
    round_consts[idx] = found_key
    front.forward()
    back.forward()

    assert front.state[0] == expected_a

for _ in range(56):
    front.forward()

hex_check = hexlify(front.finalize())
assert target_hex == hex_check

print(round_consts[:8])

con.recvuntil("Enter keys: ")
con.sendline(','.join(map(lambda n: hex(n)[2:], round_consts[:8])))

# CTF{sHa_roUnD_k3Ys_caN_b3_r3vERseD}
print(con.recvall().decode())
