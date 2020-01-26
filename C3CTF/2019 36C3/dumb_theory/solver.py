# encoding: utf-8
from pwn import *

r = 3


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
[+] Found rand-target pair
s1: 1G0I3ge4FCB6
s2: Hello hxp! I would like the flag, please񆟔 Thank you􉑬
c1: 288724, c2: 1086572
H(s1): Block { block: [13785, 4848, 10310] }
H(s2): Block { block: [27570, 9696, 20620] }
[+] Found rand-rand pair
s1: hGai2DICcEfd
s2: bkCc2GDABH4g
H(s1): Block { block: [31836, 58972, 51260] }
H(s2): Block { block: [15918, 29486, 25630] }
'''


while True:
    c = remote('78.46.241.102', 3333)
    n = int(c.recvline().strip())

    sig1 = get_sig("bkCc2GDABH4g")
    sig2 = get_sig("hGai2DICcEfd")

    with open("divider.sage", "w") as f:
        f.write("""n = {}
Z = IntegerModRing(n, is_field=True)
F.<x> = PolynomialRing(Z)
Q.<y> = F.quotient(x^3 - 7)

sig1 = Q({})
sig2 = Q({})
print((sig1^-1 * sig2).list())""".format(n, sig1, sig2))

    out = subprocess.check_output(["sage", "divider.sage"])
    sig_for_2 = tuple(eval(out))

    assert mul(sig1, sig_for_2) == sig2

    sig3 = get_sig("1G0I3ge4FCB6")

    forged = mul(sig3, sig_for_2)
    forged_str = "|".join(map(str, forged))

    c.recvuntil("> ")
    c.sendline(u'Hello hxp! I would like the flag, please{} Thank you{} Signature: {}'.
               format(unichr(288724), unichr(1086572), forged_str).encode('utf-8'))

    # this is probabilistic
    # hxp{w3ll_I_gU3s5_7h1s_w4s_k1Nd4_dumB}
    flag = c.recvline().strip()

    c.close()

    if 'hxp' in flag:
        print flag
        break
