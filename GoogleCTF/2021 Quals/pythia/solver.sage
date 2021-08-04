# With Gyejin Lee
# Based on paper: Partitioning Oracle Attacks
# Also copied some code from: https://github.com/bozhu/AES-GCM-Python/blob/master/test_gf_mul.sage
import itertools
import multiprocessing
import string

from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pwn import *


FF.<a> = GF(2 ^ 128, modulus=x ^ 128 + x ^ 7 + x ^ 2 + x + 1)
R = FF["k"]


def int2poly(integer):
    res = 0
    for i in range(128):
        # rightmost bit is x127
        res += (integer & 1) * (a ^ (127 - i))
        integer >>= 1
    return res


def poly2int(element):
    integer = element.integer_representation()
    res = 0
    for i in range(128):
        res = (res << 1) + (integer & 1)
        integer >>= 1
    return int(res)


def int2bytes(n):
    return n.to_bytes(16, "big")


def bytes2int(b):
    return int.from_bytes(b, "big")


# keyset = K, nonce = N, tag = T
def multi_collision_gcm(K, N, T):
    assert len(N) == 12

    L = int2poly(128 * len(K))
    polyT = int2poly(bytes2int(T))
    pairs = []
    for k in K:
        E_k = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
        H = int2poly(bytes2int(E_k.update(b"\x00" * 16)))
        P = int2poly(bytes2int(E_k.update(N + b"\x00\x00\x00\x01")))
        E_k.finalize()
        y = (L * H + P + polyT) * (H.inverse_of_unit() ^ 2)
        pairs.append((H, y))
    f = R.lagrange_polynomial(pairs)
    poly_X = f.list()
    X = [int2bytes(poly2int(c)) for c in poly_X]
    C = b""
    for x in X[::-1]:
        assert len(x) == 16
        C = C + x
    return C + T


passwords = [''.join(s).encode() for s in itertools.product(string.ascii_lowercase, repeat=3)]
print("Total %d" % len(passwords))

keys = []
for p in passwords:
    kdf = Scrypt(salt=b"", length=16, n=2 ** 4, r=8, p=1, backend=default_backend())
    keys.append(kdf.derive(p))

nonce = b"\x00" * 12
tag = b"\x00" * 16

chunk_size = 880


# Create ctxt for range [begin, end)
def ctxt_from_range(begin, end):
    keys_slice = keys[begin:end]
    print("  Start ciphertext!")
    ctxt = multi_collision_gcm(keys_slice, nonce, tag)
    print("  Found ciphertext!")
    return ctxt


def check_success(con, ctxt):
    con.recvuntil(">>> ")
    con.sendline("3")
    con.recvuntil(">>> ")
    con.sendline("%s,%s" % (b64encode(nonce).decode(), b64encode(ctxt).decode()))
    
    received = con.recvuntil("What you wanna do?")
    if b"Decryption successful" in received:
        return True
    else:
        return False


ranges = []

for lo in range(0, len(passwords), chunk_size):
    hi = min(len(passwords), lo + chunk_size)
    ranges.append((lo, hi))


def range_to_ctxt(r):
    lo, hi = r
    print("Precompute [%d, %d)" % (lo, hi))
    return ctxt_from_range(lo, hi)


with multiprocessing.Pool(len(ranges)) as p:
    precompute = p.map(range_to_ctxt, ranges)


con = remote("pythia.2021.ctfcompetition.com", 1337)

server_pass = []
for k in range(3):
    con.recvuntil(">>> ")
    con.sendline("1")
    con.recvuntil(">>> ")
    con.sendline(str(k))

    found = False
    for i, lo in enumerate(range(0, len(passwords), chunk_size)):
        hi = min(len(passwords), lo + chunk_size)
        print("Searching key %d - [%d, %d)" % (k, lo, hi))
        if check_success(con, precompute[i]):
            found = True
            break

    assert found

    # Range [lo, hi)
    while hi - lo > 1:
        print("Searching key %d - [%d, %d)" % (k, lo, hi))

        mid = (lo + hi) >> 1
        # do not include mid
        ctxt = ctxt_from_range(lo, mid)

        if check_success(con, ctxt):
            hi = mid
        else:
            lo = mid

    server_pass.append(passwords[lo])
    print("Key %d - %s" % (k, passwords[lo].decode()))

print(server_pass)

con.recvuntil(">>> ")
con.sendline("2")
con.recvuntil(">>> ")
con.sendline(b"".join(server_pass).decode())

con.interactive()
