import random
from hashlib import sha256
from itertools import product

from Crypto.Util.number import *
from pwn import *


def get_additive_shares(x, n, mod):
    shares = [0] * n
    shares[n - 1] = x
    for i in range(n - 1):
        shares[i] = random.randrange(mod)
        shares[n - 1] = (shares[n - 1] - shares[i]) % mod
    assert sum(shares) % mod == x
    return shares


BITS = 512


def POW():
    print("[DEBUG] POW...")
    b_postfix = r.recvline().decode().split(" = ")[1][6:].strip()
    h = r.recvline().decode().split(" = ")[1].strip()
    for brute in product("0123456789abcdef", repeat=6):
        b_prefix = "".join(brute)
        b_ = b_prefix + b_postfix
        if sha256(bytes.fromhex(b_)).hexdigest() == h:
            r.sendlineafter(b" > ", b_prefix.encode())
            return True

    assert 0, "Something went wrong.."


def generate_shared_modulus():
    print("[DEBUG] generate_shared_modulus...")

    SMALL_PRIMES = [2, 3, 5, 7, 11, 13]
    REMAINDER = {
        2: [1],
        3: [1, 2],
        5: [1, 2, 3],
        7: [1, 2, 3, 4],
        11: [1, 2, 3, 4, 5, 6],
        13: [1, 2, 3, 4, 5, 6, 7],
    }

    # Candidates of p1
    for prime in SMALL_PRIMES:
        r.sendlineafter(b" > ", " ".join(str(c) for c in REMAINDER[prime]).encode())

    # Candidates of q1
    for prime in SMALL_PRIMES:
        r.sendlineafter(b" > ", " ".join(str(c) for c in REMAINDER[prime]).encode())

    p1_enc = int(r.recvline().decode().split(" = ")[1])
    q1_enc = int(r.recvline().decode().split(" = ")[1])

    smooth = 1
    x = 1
    while True:
        x += 1
        if not isPrime(x):
            continue

        smooth *= x
        if smooth.bit_length() >= 1024:
            break

    X = [0] * 12
    X[0] = SERVER_N - p1_enc * q1_enc
    X[1] = p1_enc
    X[2] = q1_enc
    X[3] = pow(smooth, SERVER_E, SERVER_N)
    r.sendlineafter(b" > ", " ".join(str(x) for x in X).encode())

    N = int(r.recvline().decode().split(" = ")[1])

    return smooth, N


# STEP 2 - N_validity_check
def N_validity_check_client(smooth, N):
    print("[DEBUG] N_validity_check_client...")
    for _ in range(20):
        b = int(r.recvline().decode().split(" = ")[1])
        client_digest = sha256(long_to_bytes(pow(b, smooth + 1, N))).hexdigest()
        r.sendlineafter(b" > ", client_digest.encode())
        msg = r.recvline().decode()
        if msg != "good!\n":
            print(msg)
            return -1

    flag_enc = int(r.recvline().decode().split(" = ")[1])
    return flag_enc


# r = process(["python3", "./prob.py"])
r = remote("13.125.181.74", 9001)

POW()

SERVER_N = int(r.recvline().decode().split(" = ")[1])
SERVER_E = int(r.recvline().decode().split(" = ")[1])

smooth, N = generate_shared_modulus()

print(f"{smooth = }")
print(f"{N = }")

flag_enc = N_validity_check_client(smooth, N)
if flag_enc == -1:
    exit(-1)

print(f"{flag_enc = }")
