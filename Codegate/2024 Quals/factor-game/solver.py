# Solved with 5unknown
import itertools

from pwn import *
from subprocess import check_output
from re import findall


def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


from __future__ import print_function
import time

debug = False

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham

    finds a solution if:
    * b|modulus, b >= modulus^beta , 0 < beta <= 1
    * |x| < XX
    """
    #
    # init
    #
    dd = pol.degree()
    nn = dd * mm + tt

    #
    # checks
    #
    if not 0 < beta <= 1:
        raise ValueError("beta should belongs in (0, 1]")

    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    #
    # calculate bounds and display them
    #
    """
    * we want to find g(x) such that ||g(xX)|| <= b^m / sqrt(n)
    * we know LLL will give us a short vector v such that:
    ||v|| <= 2^((n - 1)/4) * det(L)^(1/n)
    * we will use that vector as a coefficient vector for our g(x)

    * so we want to satisfy:
    2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n)

    so we can obtain ||v|| < N^(beta*m) / sqrt(n) <= b^m / sqrt(n)
    (it's important to use N because we might not know b)
    """
    if debug:
        # t optimized?
        print("\n# Optimized t?\n")
        print("we want X^(n-1) < N^(beta*m) so that each vector is helpful")
        cond1 = RR(XX^(nn-1))
        print("* X^(n-1) = ", cond1)
        cond2 = pow(modulus, beta*mm)
        print("* N^(beta*m) = ", cond2)
        print("* X^(n-1) < N^(beta*m) \n-> GOOD" if cond1 < cond2 else "* X^(n-1) >= N^(beta*m) \n-> NOT GOOD")

        # bound for X
        print("\n# X bound respected?\n")
        print("we want X <= N^(((2*beta*m)/(n-1)) - ((delta*m*(m+1))/(n*(n-1)))) / 2 = M")
        print("* X =", XX)
        cond2 = RR(modulus^(((2*beta*mm)/(nn-1)) - ((dd*mm*(mm+1))/(nn*(nn-1)))) / 2)
        print("* M =", cond2)
        print("* X <= M \n-> GOOD" if XX <= cond2 else "* X > M \n-> NOT GOOD")

        # solution possible?
        print("\n# Solutions possible?\n")
        detL = RR(modulus^(dd * mm * (mm + 1) / 2) * XX^(nn * (nn - 1) / 2))
        print("we can find a solution if 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n)")
        cond1 = RR(2^((nn - 1)/4) * detL^(1/nn))
        print("* 2^((n - 1)/4) * det(L)^(1/n) = ", cond1)
        cond2 = RR(modulus^(beta*mm) / sqrt(nn))
        print("* N^(beta*m) / sqrt(n) = ", cond2)
        print("* 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n) \n-> SOLUTION WILL BE FOUND" if cond1 < cond2 else "* 2^((n - 1)/4) * det(L)^(1/n) >= N^(beta*m) / sqroot(n) \n-> NO SOLUTIONS MIGHT BE FOUND (but we never know)")

        # warning about X
        print("\n# Note that no solutions will be found _for sure_ if you don't respect:\n* |root| < X \n* b >= modulus^beta\n")

    #
    # Coppersmith revisited algo for univariate
    #

    # change ring of pol and x
    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()

    # compute polynomials
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x * XX)**jj * modulus**(mm - ii) * polZ(x * XX)**ii)
    for ii in range(tt):
        gg.append((x * XX)**ii * polZ(x * XX)**mm)

    # construct lattice B
    BB = Matrix(ZZ, nn)

    for ii in range(nn):
        for jj in range(ii+1):
            BB[ii, jj] = gg[ii][jj]

    # display basis matrix
    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    BB = flatter(BB)

    # transform shortest vector in polynomial
    new_pol = 0
    for ii in range(nn):
        new_pol += x**ii * BB[0, ii] / XX**ii

    # factor polynomial
    potential_roots = new_pol.roots()
    print("potential roots:", potential_roots)
    return potential_roots

    # test roots
    roots = []
    for root in potential_roots:
        if root[0].is_integer():
            result = polZ(ZZ(root[0]))
            if gcd(modulus, result) >= modulus^beta:
                roots.append(ZZ(root[0]))

    #
    return roots

def solve(N, p0):
    F.<x> = PolynomialRing(Zmod(N), implementation='NTL')
    f = x * 2**265 + p0
    f = f.monic()
    dd = f.degree()

    # PLAY WITH THOSE:
    beta = 0.503                             # we should have q >= N^beta
    epsilon = beta / 37                     # <= beta/7
    mm = ceil(beta**2 / (dd * epsilon))    # optimized
    tt = floor(dd * mm * ((1/beta) - 1))   # optimized
    XX = ceil(N**((beta**2/dd) - epsilon)) # we should have |diff| < X


    roots = coppersmith_howgrave_univariate(f, N, beta, mm, tt, XX)
    sol = None
    for x in roots:
        y = x[0]
        if y > 0 and type(y) == sage.rings.rational.Rational:
            sol = y
            break

    if sol is None:
        return None

    x = sol
    print('hihi', x)
    print('hihi', x * 2**265 + p0)
    print('hihi', N % (x * 2**265 + p0))

    p = int(x * 2**265 + p0)
    if N % p != 0:
        return None
    q = int(N // p)
    assert p * q == N
    return p, q


# Run with `sage -python solver.py`
def recv_hex(con, header):
    con.recvuntil(header)
    return int(con.recvline(), base=16)

known_bits = 265

con = remote("3.38.106.210", int(8287))

for i in range(10):
    con.recvuntil(f"game{i + 1} start!\n".encode())
    for j in range(5):
        p_redacted = recv_hex(con, b"p : ")
        p_mask = recv_hex(con, b"p_mask : ")
        q_redacted = recv_hex(con, b"q : ")
        q_mask = recv_hex(con, b"q_mask : ")
        N = recv_hex(con, b"N : ")

        def go(p_build, q_build, idx):
            if idx == known_bits:
                # assert p_build & p_mask == p_redacted
                # assert q_build & q_mask == q_redacted
                return [(p_build, q_build)]

            ret = []

            if p_mask & (1 << idx):
                p_bits = [(p_redacted >> idx) & 1]
            else:
                p_bits = [0, 1]

            if q_mask & (1 << idx):
                q_bits = [(q_redacted >> idx) & 1]
            else:
                q_bits = [0, 1]

            mask = (1 << idx) - 1

            for p_bit, q_bit in itertools.product(p_bits, q_bits):
                p_new = p_build | (p_bit << idx)
                q_new = q_build | (q_bit << idx)

                if (p_new * q_new) & mask == N & mask:
                    ret += go(p_new, q_new, idx + 1)

            return ret

        candidates = go(0, 0, 0)
        print(f"{len(candidates)} candidates")

        found = False
        if len(candidates) < 50:
            for p_build, q_build in candidates:
                result = solve(N, p_build)

                if result is not None:
                    p, q = result
                    print("[+] Found!")
                    print(p)
                    print(q)
                    print(p * q)
                    print(N)
                    found = True
                    break
        else:
            p = 0
            q = 0

        con.sendlineafter(b"input p in hex format : ", hex(p).encode())
        con.sendlineafter(b"input q in hex format : ", hex(q).encode())

        if found:
            break

con.interactive()
