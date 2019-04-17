# encoding: utf-8
from binascii import hexlify, unhexlify


# base -2
def A005351(n):
    s, q = '', n
    while q >= 2 or q < 0:
        q, r = divmod(q, -2)
        if r < 0:
            q += 1
            r += 2
        s += str(r)
    return int(str(q)+s[::-1], 2)  # Chai Wah Wu, Apr 10 2016


def A005351_inv(n):
    result = 0
    coeff = 1
    while n > 0:
        if n & 1:
            result += coeff
        n >>= 1
        coeff *= -2
    return result

m = unhexlify('A9 65 9A 89 3D EA F4 44 3A 84 77 75 13 13 66 95 7F 51 32 95 6B 3E 01'.replace(' ', ''))
m = A005351_inv(int(hexlify(m[::-1]), 16))

print 'm: %d' % m

# We need to know `Ack(10, 10) mod m`
# According to "MODULAR ARITHMETIC OF ITERATED POWERS" paper, it is sufficient to calculate 2↑↑(H+1) mod m
# where H = min {H: lam^H (m) = 1}
# https://www.sciencedirect.com/science/article/pii/0898122183901141/pdf

lam = []

now = m
while now > 1:
    lam.append(now)
    now = euler_phi(now)
lam.append(1)

H = len(lam) - 1
print 'H: %d' % H

# See section "5. AN ALGORITHM FOR COMPUTING A ↑^D T MODULO m"
B = [0, 0, 0]
for i in range(3, H+2):
    if lam[H+1 - i] % 2 == 0:
        # orthogonal decomposition
        V = lam[H+1 - i] // 2
        W = 2
        result = pow(2, B[i-1], V)
        if result % 2 == 1:
            result += V
    else:
        V = lam[H+1 - i]
        W = 1
        result = pow(2, B[i-1], V)
    B.append(int(result))

ack = B[H+1] - 3
print 'Ack(10, 10) mod m: %d' % ack  # 6841904303386685743535095739352445371875467071891541
print 'Encoded: %d' % A005351(ack)  # 8369635966715117454557969064641796484983418770552917
