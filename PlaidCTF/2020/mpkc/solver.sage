# Jiahui Chen et al. cryptosystem, 80-bit security
# WARNING: very slow implementation.
import sys
import re

q, n, a, s = (3, 59, 10, 25)
m = n+1-a+s
FF = GF(q)
R = PolynomialRing(FF, ["x{}".format(i) for i in range(n)])
xs = R.gens()


def combine_blocks(blocks):
    x = 0
    for i in blocks[::-1]:
        for j in i[::-1]:
            x = x*q+Integer(j)
    ss = ""
    while x > 0:
        ss = chr(x % 256) + ss
        x = x//256
    return ss


with open("output") as f:
    pk = sage_eval(re.sub(r'x(\d+)', r'xs[\1]', f.readline()), locals={'xs': xs})
    ciphertext = eval(f.readline())
    ciphertext = tuple(map(lambda v: vector(FF, v), ciphertext))

# the attack is based on: https://eprint.iacr.org/2020/053.pdf
step_1_matrix = [[0 for _ in range(n * (n+1) // 2)] for _ in range(m)]

for i in range(m):
    pki = pk[i]
    cc = 0
    # collect quadratic terms
    for (coeff, exp) in zip(pki.coefficients(), pki.exponents()):
        exp = list(exp)
        idx = []
        for exp_idx in range(n):
            while exp[exp_idx] > 0:
                exp[exp_idx] = exp[exp_idx] - 1
                idx.append(exp_idx)
        if len(idx) == 2:
            term_idx = idx[1] * (idx[1] + 1) // 2 + idx[0]
            step_1_matrix[i][term_idx] = coeff

# find the kernel
step_1_matrix = matrix(FF, step_1_matrix)
kernel_basis = step_1_matrix.kernel().basis()

# should be 49-dimensional
assert len(kernel_basis) == n-a

# generate n-a linearly independent degree-one polynomials
rs = []
ds_start = []
for y in range(n-a):
    rr = 0
    dd = 0
    for x in range(m):
        rr = rr + kernel_basis[y][x] * pk[x]

    # degree-one polynomial to matrix
    rrv = [0 for _ in range(n)]
    for (coeff, exp) in zip(rr.coefficients(), rr.exponents()):
        try:
            rrv[tuple(exp).index(1)] = coeff
        except ValueError:
            dd -= coeff

    rs.append(rrv)
    ds_start.append(dd)

rs = matrix(FF, rs)

answer_blocks = []

# solve the systems of linear equation
for (block_idx, block) in enumerate(ciphertext):
    ds = []
    for y in range(n-a):
        dd = ds_start[y]
        for x in range(m):
            dd = dd + kernel_basis[y][x] * block[x]
        ds.append(dd)

    # find a base solution and kernel basis
    ds = vector(ds)
    sol_basis = rs.transpose().kernel().basis()
    x_pre = rs.solve_right(ds)

    assert rs * x_pre == ds
    assert len(sol_basis) == a

    for i in range(q ** a):
        remain = i
        x = copy(x_pre)
        for base_idx in range(a):
            x += (remain % q) * sol_basis[base_idx]
            remain = remain // q

        if i % (3 ** 3) == 0:
            print(f"block {block_idx}, try {i}/{q ** a}")

        incorrect = False
        for m_idx in range(m):
            if not pk[m_idx](*x) == block[m_idx]:
                incorrect = True
                break

        if not incorrect:
            answer_blocks.append(x)
            break

print(combine_blocks(answer_blocks))
