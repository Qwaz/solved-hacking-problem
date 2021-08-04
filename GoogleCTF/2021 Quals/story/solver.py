import crcmod
import collections
import random
from pwn import *


Entry = collections.namedtuple("Entry", ["bits", "delta", "bit_len", "lookahead"])

crc16 = crcmod.mkCrcFun(0x18005, initCrc=0, xorOut=0)
crc32 = crcmod.mkCrcFun(0x11EDC6F41, initCrc=0, xorOut=0xFFFFFFFF)
crc64 = crcmod.mkCrcFun(0x142F0E1EBA9EA3693, initCrc=0, xorOut=0xFFFFFFFFFFFFFFFF)


# Retry until you don't get "Cannot choose from an empty sequence" error
N = 512
DECAY = 0.9
LOOKAHEAD_BITS = 8
OTHER_LEVEL = 0.4
RANDOM = 1 / 100


def bits_to_s(num):
    s = b""
    for i in range(N):
        if (num >> i) & 1:
            s += b"A"
        else:
            s += b"a"
    return s


def xor_hash(s):
    return (crc16(s) << 96) | (crc32(s) << 64) | crc64(s)


def score(delta):
    bit_len = delta.bit_length()
    if bit_len <= LOOKAHEAD_BITS:
        return (LOOKAHEAD_BITS, delta)
    else:
        lookahead = delta >> (bit_len - LOOKAHEAD_BITS)
        return (bit_len, lookahead)


def entry_from_bits(bits):
    s = bits_to_s(bits)
    delta = xor_hash(s) ^ init_hash
    bit_len, lookahead = score(delta)
    return Entry(bits, delta, bit_len, lookahead)

con = remote("story.2021.ctfcompetition.com", 1337)
con.recvuntil("Hello! Please tell me a fairy tale!")

first_s = b"a" * N
con.sendline(first_s)


init_hash = xor_hash(first_s)
print(first_s.decode())
print(hex(init_hash))

con.recvuntil("The CRC values of your text are [")
hash_from_msg = int(b"".join(con.recvuntil("].", drop=True).split(b", ")), 16)
assert init_hash == hash_from_msg

# N = 512
# goal = 0xb01ff03b4aee21fd2e9023545d84
con.recvuntil("But I am looking for a story of [")
goal = int(b"".join(con.recvuntil("].", drop=True).split(b", ")), 16)
print(hex(goal))
goal_delta = init_hash ^ goal


known_bits = set()
levels = set()

memo = [[[] for _ in range(1 << LOOKAHEAD_BITS)] for _ in range(113)]
by_level = [[] for _ in range(113)]

bests = 112


def add_entry(entry):
    global bests

    if entry.bits not in known_bits:
        memo_len = len(memo[entry.bit_len][entry.lookahead])

        if random.random() < pow(DECAY, memo_len):
            known_bits.add(entry.bits)
            memo[entry.bit_len][entry.lookahead].append(entry)
            by_level[entry.bit_len].append(entry)
            levels.add(entry.bit_len)

            if entry.bit_len < bests:
                bests = entry.bit_len
                print("Best %d" % bests)


known_bits.add(0)

for i in range(N):
    bits = 1 << i
    add_entry(entry_from_bits(bits))

while LOOKAHEAD_BITS not in levels:
    if random.random() < RANDOM:
        bits = random.randint(1, (1 << N) - 1)
        add_entry(entry_from_bits(bits))
        continue

    level1 = random.choice(list(levels))
    entry1 = random.choice(by_level[level1])

    if random.random() < OTHER_LEVEL:
        level2 = random.choice(list(levels))
    else:
        level2 = level1

    for entry2 in by_level[level2]:
        delta = entry1.delta ^ entry2.delta
        bit_len, lookahead = score(delta)
        entry = Entry(entry1.bits ^ entry2.bits, delta, bit_len, lookahead)
        add_entry(entry)

current_bits = 0
current_delta = goal_delta

while current_delta > 0:
    bit_len = current_delta.bit_length()
    entry = random.choice(by_level[bit_len])
    current_bits ^= entry.bits
    current_delta ^= entry.delta

new_story = bits_to_s(current_bits)
print(new_story.decode())
con.sendline(new_story)

print(con.recvall().strip().decode())
