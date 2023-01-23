import ast
import random
from multiprocessing import Pool

from Crypto.Util.number import inverse, long_to_bytes

with open("output.txt", "r") as f:
    es = ast.literal_eval(f.readline())
    cs = ast.literal_eval(f.readline())


def coeff_mul(coeffs, n=None):
    acc_e = 0
    acc_c = 1
    for (e, c, coeff) in zip(es, cs, coeffs):
        acc_e += coeff * e
        if n is None:
            acc_c *= pow(c, coeff)
        else:
            acc_c *= pow(c, coeff, n)

    return (acc_e, int(acc_c))


def work(work_arg):
    (basis, n) = work_arg

    if sum(basis) != 0 or basis[len(basis) - 1] != 0 or basis[len(basis) - 2] != 0:
        return None

    first = []
    second = []

    for i in range(len(basis) - 1):
        if basis[i] < 0:
            first.append(-basis[i])
            second.append(0)
        else:
            first.append(0)
            second.append(basis[i])

    return abs(coeff_mul(first, n)[1] - coeff_mul(second, n)[1])


# First stage - find N
n = None
bits = 0

small_prime = []

for i in range(2, 100):
    if is_prime(i):
        small_prime.append(i)

with Pool() as pool:
    while True:
        mat = []
        scale = 2**64

        for (i, e) in enumerate(es):
            row = [1 if i == j else 0 for j in range(len(es))]
            row.append(e * scale)
            row.append(scale)
            mat.append(row)

        bases = Matrix(mat).LLL()
        worklist = [(basis, n) for basis in bases]
        for cand in pool.map(work, worklist):
            if cand is None:
                continue

            if n is None:
                n = cand
            else:
                n = gcd(n, cand)

            bits = int(n).bit_length()
            print(f"bit_length of N: {bits}")

        for prime in small_prime:
            while n % prime == 0:
                n = n // prime
        print(f"bit_length of N: {bits}")

        if bits == 2048:
            break

# Second stage - recover m
if es[0] > es[1]:
    big = 0
    small = 1
else:
    big = 1
    small = 0

first_e = es[big] - es[small]
first_c = cs[big] * inverse(cs[small], n) % n

if es[3] > es[4]:
    big = 3
    small = 4
else:
    big = 4
    small = 3

second_e = es[big] - es[small]
second_c = cs[big] * inverse(cs[small], n) % n


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


g, x, y = egcd(first_e, second_e)
assert g == 1

m = pow(first_c, x, n) * pow(second_c, y, n) % n
print(long_to_bytes(int(m)))
