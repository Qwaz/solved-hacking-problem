# PWNLIB_NOTERM=1 sage solver.sage
# retry until you get an easy problem
import heapq
import gmpy2

from binascii import unhexlify
from functools import total_ordering
from pwn import *

from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

con = remote("yafm.2020.ctfcompetition.com", 1337)

con.recvuntil(">>> ")
con.sendline("1")
PUBKEY_TEXT = con.recvuntil("\n\n").strip().decode()

con.recvuntil(">>> ")
con.sendline("2")
FLAG = con.recvline().strip().decode()

con.close()

PUBKEY = RSA.import_key(PUBKEY_TEXT)
N = PUBKEY.n

print(PUBKEY_TEXT)
print("N = %d" % N)
print("Flag = %s" % FLAG)

KEY_SIZE = 1024
MAX_N = 1021
MAX_R = 180

print("Start!")

# build combination_table
combination_table = [[1]]
combination_table_prefix_sum = [[1]]

for n in range(1, MAX_N + 1):
    row = []
    for r in range(min(n, MAX_R) + 1):
        if r == 0 or r == n:
            row.append(1)
            continue
        row.append(combination_table[n-1][r-1] + combination_table[n-1][r])
    combination_table.append(row)
    
    row = []
    for r in range(min(n, MAX_R) + 1):
        num = combination_table[n][r]
        if r > 0:
            num += row[r-1]
        row.append(num)
    combination_table_prefix_sum.append(row)


def n_choose_r(n, r):
    return combination_table[n][r]


def n_choose_r_plus(n, r):
    if r == 0:
        return 2 ** n
    return (2 ** n) - combination_table_prefix_sum[n][r-1]


score_memo = [[None for _ in range(MAX_R + 1)] for _ in range(MAX_N + 1)]
score_memo[0][0] = 1

EARLY_BITS = 16

# estimate how likely it is to observe `bit` number of 1 bits
# when we sample `size` number of bits by
def score(size, bit):
    if bit > MAX_R or bit > size:
        return 0

    if score_memo[size][bit] is not None:
        return score_memo[size][bit]

    score = 0
    for chosen in range(bit, min(size, MAX_R) + 1):
        score_to_add = n_choose_r(MAX_N - size, MAX_R - chosen) * n_choose_r(size, chosen)
        score_to_add /= n_choose_r(MAX_N, MAX_R)
        score_to_add *= n_choose_r_plus(chosen, bit) / (2 ** chosen)
        score += score_to_add
    score_memo[size][bit] = score
    return score

@total_ordering
class Candidate:
    def __init__(self, bits, p, q, mult):
        self.bits = bits
        self.p = p
        self.q = q
        self.mult = mult
        if bits <= EARLY_BITS:
            self.score = 1
        else:
            # highest two bits are always 11, don't consider that in calculation
            self.score = score(bits - 2, gmpy2.popcount(self.p) - 2) * score(bits - 2, gmpy2.popcount(self.q) - 2)

    def __eq__(self, other):
        return self.score == other.score

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        return self.score > other.score

    def __repr__(self):
        return repr({
            "bits": self.bits,
            "p": bin(self.p)[2:].rjust(self.bits, "0"),
            "q": bin(self.q)[2:].rjust(self.bits, "0"),
            "p_bit": gmpy2.popcount(self.p),
            "q_bit": gmpy2.popcount(self.q),
            "score": "%.20f" % self.score,
        })

    def next_candidate(self, bit_p, bit_q):
        next_p = (self.p << 1) + bit_p
        next_q = (self.q << 1) + bit_q

        next_mult = (self.mult << 2) + ((bit_p * self.q + bit_q * self.p) << 1) + bit_p * bit_q

        return Candidate(self.bits + 1, next_p, next_q, next_mult)

    def next(self, heap):
        n_shifted = N >> (2 * KEY_SIZE - (self.bits + 1))
        for i, j in [(i, j) for i in [0, 1] for j in [0, 1]]:
            if self.p == self.q and i < j:
                continue

            cand = self.next_candidate(i, j)

            # compare highest bits
            cand_shifted = cand.mult >> cand.bits 
            if cand_shifted == n_shifted or cand_shifted + 1 == n_shifted:
                heapq.heappush(heap, cand)


beta = 0.5
epsilon = beta^2 / 7

max_unknown = floor(KEY_SIZE * 2 * (beta^2 - epsilon))

# show the requirement
print("Needs upper %d bits of %d bits" % (KEY_SIZE - max_unknown, KEY_SIZE))

KNOWN_BITS = 600
assert KNOWN_BITS >= KEY_SIZE - max_unknown


# Coppersmith code taken from: http://inaz2.hatenablog.com/entry/2016/01/20/022936
def coppersmith(cand):
    unknown_bits = KEY_SIZE - KNOWN_BITS

    q = None
    pbar = cand << unknown_bits

    PR.<x> = PolynomialRing(Zmod(N))
    f = x + pbar

    result = f.small_roots(X=2^unknown_bits, beta=0.3)
    for p_remain in result:
        p = int(pbar + p_remain)
        if p != 0 and p != N and N % p == 0:
            q = N // int(p)
            break
    
    if q is None:
        return None

    assert p * q == N

    return (p, q)


heap = [Candidate(2, 3, 3, 9)]

current_max = 0

print("Finding an answer...")
while len(heap) > 0:
    elem = heapq.heappop(heap)

    if elem.bits == current_max + 10:
        current_max = elem.bits
        print("Current max: %d" % current_max)

    if elem.bits == KNOWN_BITS:
        print(elem)
        ans = coppersmith(elem.p)
        if ans is not None:
            break
        ans = coppersmith(elem.q)
        if ans is not None:
            break
    else:
        elem.next(heap)

p, q = ans

print("P: %d" % p)
print("Q: %d" % q)

d = inverse(PUBKEY.e, (p-1) * (q-1))

key = RSA.construct((N, PUBKEY.e, int(d), int(p), int(q)))
cipher = PKCS1_OAEP.new(key)

# CTF{l0w_entr0py_1s_alw4ys_4_n1ghtmar3_I_h4v3_sp0ken}
print(cipher.decrypt(unhexlify(FLAG)).decode().strip())
