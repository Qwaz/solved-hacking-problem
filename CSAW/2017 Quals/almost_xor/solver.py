from z3 import *

CHAR_LEN = 48
BIT_LEN = CHAR_LEN * 8

c = '809fdd88dafa96e3ee60c8f179f2d88990ef4fe3e252ccf462deae51872673dcd34cc9f55380cb86951b8be3d8429839'


def printable(bv):
    return And(BitVecVal(0x20, 8) <= bv, bv <= BitVecVal(0x7E, 8))


valid_n = [2, 3, 4, 6]

for n in valid_n:
    for key_len in range(2, 12):
        key_bit_len = key_len * 8
        key_offset = ((BIT_LEN - 1) // key_bit_len + 1) * key_bit_len - BIT_LEN

        s = Solver()

        result = BitVec('r', BIT_LEN)
        plain = BitVec('p', BIT_LEN)
        double_key = BitVec('k', key_bit_len*2)

        s.add(result == BitVecVal(int(c, 16), BIT_LEN))

        s.add(BitVecVal(ord('f'), 8) == Extract(BIT_LEN-1, BIT_LEN-8, plain))
        s.add(BitVecVal(ord('l'), 8) == Extract(BIT_LEN-9, BIT_LEN-16, plain))
        s.add(BitVecVal(ord('a'), 8) == Extract(BIT_LEN-17, BIT_LEN-24, plain))
        s.add(BitVecVal(ord('g'), 8) == Extract(BIT_LEN-25, BIT_LEN-32, plain))
        s.add(BitVecVal(ord('{'), 8) == Extract(BIT_LEN-33, BIT_LEN-40, plain))
        s.add(BitVecVal(ord('}'), 8) == Extract(7, 0, plain))

        for i in range(0, BIT_LEN, 8):
            s.add(printable(Extract(i+7, i, plain)))

        s.add(Extract(key_bit_len-1, 0, double_key) == Extract(key_bit_len*2-1, key_bit_len, double_key))

        for i in range(0, BIT_LEN, n):
            extracted_key = Extract((i+key_offset)%key_bit_len + n-1, (i+key_offset)%key_bit_len, double_key)
            s.add(Extract(i+n-1, i, result) == Extract(i+n-1, i, plain)+extracted_key)

        while s.check() == sat:
            print n, key_len
            
            m = s.model()
            bit_result = bin(m[result].as_long())[2:].zfill(BIT_LEN)
            bit_plain = bin(m[plain].as_long())[2:].zfill(BIT_LEN)
            bit_key = bin(m[double_key].as_long())[2:][-key_bit_len:]

            print ('%096x' % m[plain].as_long()).decode('hex')
            
            s.add(plain != m[plain])
