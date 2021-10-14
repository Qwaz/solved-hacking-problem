from hashlib import sha256
from secret import flag

global p, alphabet
p = 71
alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'

flag = flag.lstrip('flag{').rstrip('}')
assert len(flag) == 24
assert sha256(flag.encode()).hexdigest() == '95cb911a467482cc0f879861532e9ec7680b0846b48a9de25fb13b01c583d9f8'

def cross(m):
    return alphabet.index(m)

def prepare(msg):
    A = zero_matrix(GF(p), 11, 11)
    for k in range(len(msg)):
        i, j = 5*k // 11, 5*k % 11
        A[i, j] = cross(msg[k])
    return A

def keygen():
    R = random_matrix(GF(p), 11, 11)
    while True:
        S = random_matrix(GF(p), 11, 11)
        if S.rank() == 11:
            _, L, U = S.LU()
            return R, (L, U)

def encrypt(A, pk, sk):
    R, L, U = pk, sk[0], sk[1]
    S = L * U
    X = A + R
    Y = S * X
    E = L.inverse() * Y
    return E

A = prepare(flag)
pk, sk = keygen()
E = encrypt(A, pk, sk)
print(f'E = \n{E}')
print(f'pk = \n{pk}')
'''
E = 
[31 45 41 12 36 43 45 51 25  2 64]
[68 24 32 35 52 13 64 10 14  2 40]
[34 34 64 32 67 25 21 57 31  6 56]
[ 7 17 12 33 54 66 28 25 40 23 26]
[14 65 70 35 67 55 47 36 36 42 57]
[68 28 33  0 45 52 59 29 52 41 46]
[60 35  0 21 24 44 49 51  1  6 35]
[20 21 44 57 23 35 30 28 16 23  0]
[24 64 54 53 35 42 40 17  3  0 36]
[32 53 39 47 39 56 52 15 39  8  9]
[ 7 57 43  5 38 59  2 25  2 67 12]
pk = 
[53 28 20 41 32 17 13 46 34 37 24]
[ 0  9 54 25 36  1 21 24 56 51 24]
[61 41 10 56 57 28 49  4 44 70 34]
[47 58 36 53 68 66 34 69 22 25 39]
[ 4 70 21 36 53 26 59 51  3 44 28]
[41 23 39 37  1 28 63 64 37 35 51]
[43 31 16 36 45  5 35 52  7 45 41]
[26  3 54 58 50 37 27 49  3 46 11]
[14 48 18 46 59 64 62 31 42 41 65]
[17 50 68 10 24 40 58 46 48 14 58]
[46 24 48 32 16  1 27 18 27 17 20]
'''