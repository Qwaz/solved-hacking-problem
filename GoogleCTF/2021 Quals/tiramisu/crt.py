import pwnlib
import challenge_pb2
import struct

from curve import Coord, EC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from multiprocessing import Pool

FLAG_CIPHER_KDF_INFO = b"Flag Cipher v1.0"

class AuthCipher(object):
    def __init__(self, secret, cipher_info):
        self.cipher_key = self.derive_key(secret, cipher_info)

    def derive_key(self, secret, info):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=info,
        )
        return hkdf.derive(secret)

    def decrypt(self, iv, ciphertext):
        cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        pt = decryptor.update(ciphertext) + decryptor.finalize()
        return pt


p224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
a224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
b224 = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4

gx224 = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
gy224 = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34

crt_table = [
    (5441, 203),
    (2099, 885),
    (7723, 303),
    (2203, 149),
    #
    (2503, 1077),
    (5807, 1148),
    (6691, 1545),
    (4229, 931),
    #
    (2473, 350),
    (4483, 1130),
    (2753, 1021),
    (2659, 51),
    #
    (3877, 1364),
    (2141, 953),
    (2593, 269),
    (4289, 1735),
    #
    (4691, 437),
    (3301, 784),
    (3019, 21),
]


def handle_pow(tube):
    raise NotImplemented()


def read_message(tube, typ):
    n = struct.unpack("<L", tube.recvnb(4))[0]
    buf = tube.recvnb(n)
    msg = typ()
    msg.ParseFromString(buf)
    return msg


def proto2key(key):
    assert isinstance(key, challenge_pb2.EcdhKey)
    assert key.curve == challenge_pb2.EcdhKey.CurveID.SECP224R1
    x = int.from_bytes(key.public.x, "big")
    y = int.from_bytes(key.public.y, "big")
    return (x, y)


con = pwnlib.tubes.remote.remote("tiramisu.2021.ctfcompetition.com", 1337)
con.recvuntil("== proof-of-work: ")
if con.recvline().startswith(b"enabled"):
    handle_pow()

server_hello = read_message(con, challenge_pb2.ServerHello)
px, py = proto2key(server_hello.key)

iv = server_hello.encrypted_flag.iv
ct = server_hello.encrypted_flag.data
mac = server_hello.encrypted_flag.mac

con.close()

# x = 16172896427079531402065391174021745391759293127844103141392333432900
# y = 3771244459121791372570158792354692313003593392921088306467285612598
# iv = b's@v\xd5g\xe0\t*\xbc\xe1\t\x15\x82UC}'
# ct = b'>}"B\xea"WgA\x9c*\x0cp\xd6b\\O6\xfc\xa8\x8fK\xe3\xdcU\xfc\xaa~\xb7\x16\xd5\x8aJ\xcf8M\xec{q\x99\x81\xc8\xe9yyj`3_\x94^\xcb\x84P\x80\xd3\x9b='
# mac = b'\xcc\x1d\xfd\xf0\x16\x14\x8e\x04\xdd._\xf0H\x9e\xaff9h\x87\x94\xf1\xa7\xf4\x96]\xed\xcc\x18D\xe1\xa9\x8a'


curve = EC(a224, b224, p224)
g = Coord(gx224, gy224)
pub = Coord(px, py)

reuse_table = []

prod = 1
for (p, rem) in crt_table:
    prod *= p

for (p, rem) in crt_table:
    pp = prod // p
    inv = pow(pp, -1, p)
    reuse_table.append(pp * inv)


def run(t):
    d_try = 0
    for i in range(len(crt_table)):
        p, rem = crt_table[i]
        if (t >> i) & 1:
            d_try += rem * reuse_table[i]
        else:
            d_try += (p - rem) * reuse_table[i]
    d_try %= prod

    pub_try = curve.mul(g, d_try)
    if pub_try == pub:
        print("Found d: %d" % d_try)
        return d_try
    return None


with Pool(64) as p:
    result = p.map(run, range(1 << len(crt_table)))

for d_try in result:
    if d_try is not None:
        d = d_try

secret = int.to_bytes(d, 224 // 8, 'big')
cipher = AuthCipher(secret, FLAG_CIPHER_KDF_INFO)
print(cipher.decrypt(iv, ct))
