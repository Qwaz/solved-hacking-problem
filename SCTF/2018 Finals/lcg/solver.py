from pwn import *


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


def guess(num):
    p.sendline(str(num))
    return int(p.recvline())

p = remote('lcg.eatpwnnosleep.com', 12345)

d = 0xdeadbeef
N = 16

X = []
for i in range(N):
    X.append(guess(0))

Y = []
for i in range(1, N):
    Y.append(X[i] + d * X[i-1])

Z = []
for i in range(1, N - 1):
    Z.append(Y[i] - Y[i-1])

m = None
for i in range(2, N - 2):
    m0, m1, m2 = Z[i-2], Z[i-1], Z[i]
    m_next = m1*m1 - m0*m2
    if m is None:
        m = m_next
    else:
        m = egcd(m, m_next)[0]
if m < 0:
    m = -m
log.success('M: 0x%x' % m)

k = (Y[2] - Y[1]) * modinv(Y[1] - Y[0], m) % m
log.success('K: 0x%x' % k)

z = (Y[1] - k * Y[0]) % m
log.success('Z: 0x%x' % z)

s0 = X[N - 2]
s1 = X[N - 1]
for i in range(16):
    num = ((k - d) * s1 + k * d * s0 + z) % m
    p.sendline(str(num))
    s0, s1 = s1, num

p.recvline()
print p.recvline()
