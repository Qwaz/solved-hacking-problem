from Crypto.Util.number import *
from collections import deque

n = 134896036104102133446208954973118530800743044711419303630456535295204304771800100892609593430702833309387082353959992161865438523195671760946142657809228938824313865760630832980160727407084204864544706387890655083179518455155520501821681606874346463698215916627632418223019328444607858743434475109717014763667
k = 131

enc = 84329776255618646348016649734028295037597157542985867506958273359305624184282146866144159754298613694885173220275408231387000884549683819822991588176788392625802461171856762214917805903544785532328453620624644896107723229373581460638987146506975123149045044762903664396325969329482406959546962473688947985096

primes = [2]
current = 3
while len(primes) < k:
    is_prime = True
    for p in primes:
        if current % p == 0:
            is_prime = False
            break
    if is_prime:
        primes.append(current)
    current += 2

def num_to_bits(num):
    result = deque()
    while num > 0:
        result.appendleft(num & 1)
        num = num >> 1
    return list(result)

def extend_bits(sz, arr):
    rem = len(arr) % sz
    if rem > 0:
        arr = [0] * (sz - rem) + arr
    return arr

s = "the flag is hitcon{" + "\x00" * 6 + "}"
num = bytes_to_long(s)
bits = num_to_bits(num)
extended = list(reversed(extend_bits(8, bits)))
ori_len = len(extended)
extended_bits = extend_bits(k, extended)
ori_len_bits = num_to_bits(ori_len)
extended_ori_len_bits = extend_bits(k, ori_len_bits)
final_bits = extended_ori_len_bits + extended_bits
rev_final = list(reversed(final_bits))

def unwind(num, q, arr):
    for (a, p) in zip(arr, primes):
        if a == 1:
            num = num * inverse(pow(p, q, n), n) % n
    return num

enc = unwind(enc, 4, rev_final[:k])
enc = unwind(enc, 2, rev_final[k:2*k])
enc = unwind(enc, 1, rev_final[2*k:3*k])

print enc

num = 0
coff = 1

start_i = primes.index(79)
for i in range(start_i, start_i + 48):
    num <<= 1
    if enc % primes[i] == 0:
        num += 1

# hitcon{v@!>A#}
print "hitcon{%s}" % long_to_bytes(num)
