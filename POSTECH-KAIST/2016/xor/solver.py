#!/usr/bin/python


def is_cyclic(str, cycle_len):
    target = str[:cycle_len]

    i = 1
    while i * cycle_len < len(str):
        tmp = str[i * cycle_len: (i+1) * cycle_len]
        if target[:len(tmp)] != tmp:
            return False
        i += 1
    return True


f = open('enc', 'rb')
original = f.read()
f.close()

full_len = len(original)  # 399 = 3 * 7 * 19

primes = []

for i in range(2, 256):
    is_prime = True
    for j in range(2, i):
        if i % j == 0:
            is_prime = False
    if is_prime:
        primes.append(i)

ans_count = 0
for p in primes[::-1]:
    p_removed = ''
    for i in range(full_len):
        p_removed += chr(ord(original[i]) ^ i ** p % p)

    for r in range(3, full_len):
        if full_len % r != 0:
            continue
        flag_len = full_len // r

        for key_len in range(1, flag_len):
            for key_first in range(256):
                key = [0 for i in range(key_len)]
                key[0] = key_first

                # generate_key
                for x in range(key_len):
                    prev_key_index = (x * flag_len) % key_len
                    this_key_index = ((x+1) * flag_len) % key_len

                    key[this_key_index] = (
                        key[prev_key_index] ^
                        ord(p_removed[prev_key_index]) ^
                        ord(p_removed[prev_key_index + flag_len])
                    )

                # validate key
                valid_key = True
                for i in range(flag_len):
                    if key[i % key_len] ^ key[(i+flag_len) % key_len] != ord(p_removed[i]) ^ ord(p_removed[i + flag_len]):
                        valid_key = False
                        break

                if not valid_key:
                    continue

                r_removed = ''
                for i in range(full_len):
                    r_removed += chr(ord(p_removed[i]) ^ key[i % key_len])

                if is_cyclic(r_removed, flag_len):
                    '''==== answer candidate %2d ====
p: %d
r: %d
key_len: %d
key: %s
enc: %s
==============================''' % (
                        ans_count,
                        p,
                        r,
                        key_len,
                        str(key),
                        str(map(lambda c: ord(c), r_removed))
                    )
                    ans_count += 1

                    # reverse message
                    for q in primes:
                        try:
                            table_len = q ** 2 - 6 * q + 6
                            reverse_table = [0 for i in range(table_len)]

                            for i in range(255, -1, -1):
                                reverse_table[i ** q % table_len] = chr(i)
                            ans = ''
                            for c in r_removed[:flag_len]:
                                ans += reverse_table[ord(c)]
                            print ans
                        except Exception as e:
                            pass

# enc += chr( i ** p % p ^ ord(msg[i]) ** q % (q ** 2 - 6 * q + 6) ^ ord(key[r * i % len(key)]) )
