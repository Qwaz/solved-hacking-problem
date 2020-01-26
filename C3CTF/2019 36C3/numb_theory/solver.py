# encoding: utf-8
from pwn import *

r = 4


def mul(a, b):
    z = [0, 0]*r
    for i in range(r):
        for j in range(r):
            z[i+j] += a[i]*b[j]
    while len(z) > r:
        y = z.pop()
        z[-r] += sum(map(eval, 'yyyyyyy'))
    return tuple(t % n for t in z)


def exp(x, k):
    y = [not i for i in range(r)]
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            y = mul(y, x)
        x = mul(x, x)
    return y


def H(msg):
    h = hashlib.sha256(msg.encode('utf-8')).digest()
    v = tuple(c+1 for c in struct.unpack('>%sH' % r, h[:r+r]))
    return v


def get_sig(s):
    c.recvuntil("> ")
    c.sendline(s)
    sig = tuple(map(int, c.recvline().strip().split('|')))
    return sig


'''
[+] Found rand-rand pair
s1: BAdfD4jK6be7EHga
s2: kF89c7hfHDgEBj25
H(s1): Block (39336, 43864, 26148, 33266)
H(s2): Block (19668, 21932, 13074, 16633)
[+] Found rand-target pair
s1: p!MoNw]4Os
s2: Hello hxp! I would like the flag, please􈨧  Thank you򲊾�
c1: 1083943, c2: 729790
H(s1): Block (43022, 14508, 39894, 10398)
H(s2): Block (21511, 7254, 19947, 5199)
'''


while True:
    c = remote('78.46.199.5', 4444)
    n = int(c.recvline().strip())

    sig1 = get_sig("BAdfD4jK6be7EHga")
    sig2 = get_sig("kF89c7hfHDgEBj25")

    with open("divider.sage", "w") as f:
        f.write("""n = {}
Z = IntegerModRing(n, is_field=True)
F.<x> = PolynomialRing(Z)
Q.<y> = F.quotient(x^4 - 7)

sig1 = Q({})
sig2 = Q({})
print((sig1^-1 * sig2).list())""".format(n, sig1, sig2))

    out = subprocess.check_output(["sage", "divider.sage"])
    sig_for_inv2 = tuple(eval(out))

    assert mul(sig1, sig_for_inv2) == sig2

    sig3 = get_sig("p!MoNw]4Os")

    forged = mul(sig3, sig_for_inv2)
    forged_str = "|".join(map(str, forged))

    c.recvuntil("> ")
    c.sendline(u'Hello hxp! I would like the flag, please{} Thank you{} Signature: {}'.
               format(unichr(1083943), unichr(729790), forged_str).encode('utf-8'))

    # this is probabilistic
    # hxp{Num6er_Th30Ry_m4ke5_mY_Br41n_g0_nUmb}
    flag = c.recvline().strip()

    c.close()

    if 'hxp' in flag:
        print flag
        break
