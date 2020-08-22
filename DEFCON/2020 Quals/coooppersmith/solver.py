from pwn import *
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from ast import literal_eval
from binascii import hexlify, unhexlify
import fuckpy3
import subprocess


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

proc = remote("coooppersmith.challenges.ooo", 5000)

proc.recvuntil("no more than 120: ")
seed_prefix = 1 << (120 * 4 - 1)
seed_str = hexlify(seed_prefix.to_bytes(60, byteorder='big')).str()
proc.sendline(seed_str)

proc.recvuntil("Your public key:")
key_str = proc.recvuntil("-----END RSA PUBLIC KEY-----").strip()
pub_key = RSA.import_key(key_str)

for offset in range(2 ** 16):
    seed = (seed_prefix << 32) + offset
    if (pub_key.n - 1) % seed == 0:
        break

log.success("Seed: 0x%x" % seed)
two_seed = seed * 2
n_divided = (pub_key.n - 1) // two_seed

rp_rq_sum = n_divided % two_seed
rp_rq_mul = n_divided // two_seed

log.success("rp + rq = 0x%x" % rp_rq_sum)
log.success("rp * rq = 0x%x" % rp_rq_mul)

min_rp = 1
max_rp = rp_rq_sum // 2

while max_rp > min_rp:
    rp = (min_rp + max_rp) >> 1
    rq = rp_rq_sum - rp
    if rp * rq > rp_rq_mul:
        max_rp = rp - 1
    elif rp * rq < rp_rq_mul:
        min_rp = rp + 1
    else:
        break

# you may need to retry a few times
assert rp + rq == rp_rq_sum
assert rp * rq == rp_rq_mul

log.success("rp = 0x%x" % rp)
log.success("rq = 0x%x" % rq)

P = 2 * rp * seed + 1
Q = 2 * rq * seed + 1

N = pub_key.n
E = pub_key.e

log.info(f"N = {N}")
log.info(f"p = {P}")
log.info(f"q = {Q}")
assert P * Q == N

D = modinv(E, (P-1) * (Q-1))

priv_key = RSA.construct((N, E, D, P, Q))
cipher = PKCS1_v1_5.new(priv_key)

proc.recvuntil("Question: \n")
question_hex = proc.recvline().strip().str()
question_bytes = unhexlify(question_hex)
question_str = cipher.decrypt(question_bytes, None)
splitted = question_str.split()

n1 = int(splitted[4])
n2 = int(splitted[6][:-1])

proc.sendline(str(n1 + n2))

proc.recvuntil("Your flag message:\n")
flag_hex = proc.recvline().strip()
flag_bytes = unhexlify(flag_hex)
flag_str = cipher.decrypt(flag_bytes, None)

# OOO{Be_A_Flexible_Coppersmith}
print(flag_str.str())
