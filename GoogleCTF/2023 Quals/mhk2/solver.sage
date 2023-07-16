from output import cipher, params

N = 256
LAMBDA = 32  # LLL scaling

a1 = params["a1"]
a2 = params["a2"]

b = params["b"]

b1 = params["c"]
b2 = [(b1[i] + b[i]) % 2 for i in range(N)]

assert N == len(a1) == len(a2) == len(b) == len(b1) == len(b2)


def solve_one(v, sum_v, bits):
    m = []
    for i in range(N):
        t = [0] * (N + 2)
        t[i] = 1
        t[N] = -LAMBDA * v[i]
        m.append(t)
    # Final row
    t = [0] * (N + 2)
    t[N] = LAMBDA * sum_v
    t[N + 1] = 1
    m.append(t)

    mat = matrix(ZZ, m)
    lll = mat.LLL()

    for row in lll:
        if row[N + 1] == 1 and row[N] == 0:
            coeff_row = row
            break
    else:
        print("No row found...")
        exit(1)

    bit = 0
    for i in range(N):
        bit = (bit + bits[i] * coeff_row[i]) % 2

    return bit


if len(cipher) % 8 == 0:
    plaintext_bin = ""
else:
    plaintext_bin = "0" * (8 - len(cipher) % 8)

for (i, c_bit) in enumerate(cipher):
    m1 = solve_one(a1, c_bit[0], b2)
    m2 = solve_one(a2, c_bit[1], b1)
    print(m1, m2)

    plaintext_bin += str((m1 + m2) % 2)
    print(f"{i:03}/{len(cipher)}: {plaintext_bin}")

split_bin = [plaintext_bin[i : i + 8] for i in range(0, len(plaintext_bin), 8)]

plaintext = ""
for seq in split_bin:
    plaintext += chr(int(seq, 2))

# CTF{faNNYPAcKs_ARe_4maZiNg_AnD_und3Rr@t3d}
print(plaintext)
