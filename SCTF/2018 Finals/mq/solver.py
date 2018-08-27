from binascii import unhexlify
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


def output(index):
    payload = ['\x00' for _ in range(N)]
    if index is not None:
        payload[index] = '\x01'
    p.send(''.join(payload))
    result = p.recvline().strip()
    assert len(result) == 4

    return int(result[2:4], 16)

p = remote('mq.eatpwnnosleep.com', 12345)

P = 131
N = 32
Q = [[0 for _ in range(N)] for _ in range(N)]
U = [0 for _ in range(N)]
C = 0

tokens = p.recvline().strip().split(' + ')

for token in tokens:
    sp = map(int, token.split('x'))
    if len(sp) == 3:
        Q[sp[1] - 1][sp[2] - 1] = sp[0]
        Q[sp[2] - 1][sp[1] - 1] = sp[0]
    elif len(sp) == 2:
        U[sp[1] - 1] = sp[0]
    elif len(sp) == 1:
        C = sp[0]

orig = output(None)

A = [[0 for _ in range(N + 1)] for _ in range(N)]
for i in range(N):
    current = (output(i) - orig - U[i] - Q[i][i]) % P
    A[i][N] = current
    for j in range(N):
        if i == j:
            A[i][j] = 2 * Q[i][j]
        else:
            A[i][j] = Q[i][j]


for i in range(0, N):
    # Search for maximum in this column
    maxEl = abs(A[i][i])
    maxRow = i
    for k in range(i+1, N):
        if abs(A[k][i]) > maxEl:
            maxEl = abs(A[k][i])
            maxRow = k

    # Swap maximum row with current row (column by column)
    for k in range(i, N+1):
        A[maxRow][k], A[i][k] = A[i][k], A[maxRow][k]

    # Make all rows below this one 0 in current column
    for k in range(i+1, N):
        c = (-A[k][i] * modinv(A[i][i], P)) % P
        for j in range(i, N+1):
            if i == j:
                A[k][j] = 0
            else:
                A[k][j] = (A[k][j] + c * A[i][j]) % P

# Solve equation Ax=b for an upper triangular matrix A
x = [0 for i in range(N)]
for i in range(N-1, -1, -1):
    x[i] = A[i][N] * modinv(A[i][i], P) % P
    for k in range(i-1, -1, -1):
        A[k][N] = (A[k][N] - A[k][i] * x[i]) % P

print ''.join(map(chr, x))
