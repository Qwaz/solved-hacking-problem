from sage.all import *
from Crypto.Util.number import long_to_bytes
import sys

N = 63

const1 = 0xA5118FA1C766BF85
const2 = 0xE273A75A9956DAA7


def gmul(a, b):
    acc = 0
    while b > 0:
        if b & 1:
            acc = acc.__xor__(a)
        a = a << 1
        if a & (1 << N):
            a = (a.__xor__(const2)) & ((1 << 64) - 1)
        b >>= 1
    return acc


data = [0x254847ec89dc651, 0x40bd6e5607da03bf, 0x45620b52aa48fa85, 0x493cd4e5fc020560]
g.<z> = GF(2^63, modulus=GF(2^64).fetch_int(const2), check_irreducible=False)
target = g.fetch_int(const1.__xor__(const2))
inv_target = ((target) ^ (-1)).integer_representation()

for current in data:
    result = gmul(current, inv_target)
    sys.stdout.write(long_to_bytes(result)[::-1])
sys.stdout.write('\n')
