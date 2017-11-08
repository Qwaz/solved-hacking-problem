# c++ mt19937 reverser powered by z3
from z3 import *


class ClassicMT(object):
    def __init__(self, symMT, state):
        self.state = state

        self.xor_mask = symMT.xor_mask

        self.u = symMT.u
        self.d = symMT.d
        self.s = symMT.s
        self.b = symMT.b
        self.t = symMT.t
        self.c = symMT.c
        self.l = symMT.l
        self.f = symMT.f

        self.index = 0

    def generate(self):
        y = self.state[self.index]
        y ^= y >> self.u
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        self.index = (self.index + 1) % 624
        if self.index == 0:
            self.twist()
        return y

    def twist(self):
        b2 = 2**31
        b3 = b2 - 1
        for i in range(624):
            y = (self.state[i] & b2) + (self.state[(i+1) % 624] & b3)
            self.state[i] = self.state[(i+397) % 624] ^ (y >> 1)
            self.state[i] ^= (y & 1) * self.xor_mask


class SymbolicMT(object):
    def __init__(self):
        self.solver = Solver()
        self.state = [BitVec('s'+str(i), 32) for i in range(624)]
        self.xor_mask = 0x9908b0df

        self.bit_cnt = 0
        self.gen_cnt = 0

        self.u = 11
        self.d = 0xffffffff
        self.s = 7
        self.b = 0x9d2c5680
        self.t = 15
        self.c = 0xefc60000
        self.l = 18
        self.f = 1812433253

        self.index = 0

    def generate(self):
        self.gen_cnt += 1

        y = self.state[self.index]
        y ^= LShR(y, self.u)
        y ^= (y << self.s) & BitVecVal(self.b, 32)
        y ^= (y << self.t) & BitVecVal(self.c, 32)
        y ^= LShR(y, self.l)

        self.index = (self.index + 1) % 624
        if self.index == 0:
            self.twist()
        return simplify(y)

    def twist(self):
        b2 = 2**31
        b3 = b2 - 1
        for i in range(624):
            y = (self.state[i] & b2) + (self.state[(i+1) % 624] & b3)
            self.state[i] = self.state[(i+397) % 624] ^ LShR(y, 1)
            self.state[i] ^= (y & 1) * self.xor_mask
            self.state[i] = simplify(self.state[i])

    def expect(self, bit, val):
        self.bit_cnt += bit
        v = self.generate()
        self.solver.add(Extract(bit-1, 0, v) == val)

    def check(self):
        return self.solver.check()

    def fix(self, initial=False):
        assert self.solver.check() == sat
        self.model = self.solver.model()

        state_original = []
        for i in range(624):
            state_original.append(
                self.model[BitVec('s%d' % i, 32)].as_long()
            )

        mt = ClassicMT(self, state_original)
        if not initial:
            for i in range(self.gen_cnt):
                mt.generate()

        return mt
