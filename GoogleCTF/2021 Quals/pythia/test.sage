# With Gyejin Lee
# Based on paper: Partitioning Oracle Attacks
# Also copied some code from: https://github.com/bozhu/AES-GCM-Python/blob/master/test_gf_mul.sage
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
        y = (L * H + P + polyT) * (H.inverse_of_unit() ^ 2)
        pairs.append((H, y))
    f = R.lagrange_polynomial(pairs)
    for (H, y) in pairs:
        assert f(H) == y
    poly_X = f.list()
    X = [int2bytes(poly2int(c)) for c in poly_X]
    C = b""
    for x in X[::-1]:
        assert len(x) == 16
        C = C + x
    return C + T


passwords = [b"abc", b"def", b"ghi"]

keys = []
for p in passwords:
    kdf = Scrypt(salt=b"", length=16, n=2 ** 4, r=8, p=1, backend=default_backend())
    keys.append(kdf.derive(p))

nonce = b"\x00" * 12
tag = b"\x00" * 16
ctxt = multi_collision_gcm(keys, nonce, tag)

print(ctxt)

# Testing
print("Testing")

key = keys[0]
nonce = b"\x00" * 12

cipher = AESGCM(key)
print(cipher.encrypt(nonce, b'y\xdf\x1f\xa0\x94V\x0f\xd3\xdfr\x1f?C\xe20\x7f', associated_data=None))

E0 = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
H0 = E0.update(b"\x00" * 16)

polyH0 = int2poly(bytes2int(H0))
polyLen = int2poly(128)
print(int2bytes(poly2int(polyH0 * polyLen + int2poly(bytes2int(E0.update(nonce + b"\x00\x00\x00\x01"))))))

for (i, key) in enumerate(keys):
    cipher = AESGCM(key)
    cipher.decrypt(nonce, ctxt, associated_data=None)
