import itertools
from hashlib import sha256

p = 71

alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'

E = matrix(GF(p), [
    [31, 45, 41, 12, 36, 43, 45, 51, 25,  2, 64],
    [68, 24, 32, 35, 52, 13, 64, 10, 14,  2, 40],
    [34, 34, 64, 32, 67, 25, 21, 57, 31,  6, 56],
    [ 7, 17, 12, 33, 54, 66, 28, 25, 40, 23, 26],
    [14, 65, 70, 35, 67, 55, 47, 36, 36, 42, 57],
    [68, 28, 33,  0, 45, 52, 59, 29, 52, 41, 46],
    [60, 35,  0, 21, 24, 44, 49, 51,  1,  6, 35],
    [20, 21, 44, 57, 23, 35, 30, 28, 16, 23,  0],
    [24, 64, 54, 53, 35, 42, 40, 17,  3,  0, 36],
    [32, 53, 39, 47, 39, 56, 52, 15, 39,  8,  9],
    [ 7, 57, 43,  5, 38, 59,  2, 25,  2, 67, 12],
])

pk = matrix(GF(p), [
    [53, 28, 20, 41, 32, 17, 13, 46, 34, 37, 24],
    [ 0,  9, 54, 25, 36,  1, 21, 24, 56, 51, 24],
    [61, 41, 10, 56, 57, 28, 49,  4, 44, 70, 34],
    [47, 58, 36, 53, 68, 66, 34, 69, 22, 25, 39],
    [ 4, 70, 21, 36, 53, 26, 59, 51,  3, 44, 28],
    [41, 23, 39, 37,  1, 28, 63, 64, 37, 35, 51],
    [43, 31, 16, 36, 45,  5, 35, 52,  7, 45, 41],
    [26,  3, 54, 58, 50, 37, 27, 49,  3, 46, 11],
    [14, 48, 18, 46, 59, 64, 62, 31, 42, 41, 65],
    [17, 50, 68, 10, 24, 40, 58, 46, 48, 14, 58],
    [46, 24, 48, 32, 16,  1, 27, 18, 27, 17, 20],
])


flag_mark = zero_matrix(GF(p), 11, 11)
for k in range(24):
    i, j = 5*k // 11, 5*k % 11
    flag_mark[i, j] = 1

U_inv = zero_matrix(GF(p), 11, 11)

for row in range(10, 1, -1):
    ans_size = 11 - row

    count = 0
    for col in range(11):
        if flag_mark[row, col] == 1:
            continue
        count += 1

    left = zero_matrix(GF(p), ans_size, count)
    right = zero_vector(GF(p), count)

    count = 0
    for col in range(11):
        if flag_mark[row, col] == 1:
            continue
        right[count] = pk[row, col]
        for y in range(ans_size):
            left[y, count] = E[11 - ans_size + y, col]
        count += 1

    print(f"Row: {row}")
    print(f"Left:\n{left}")
    print(f"Right:\n{right}")

    ans = left.solve_left(right)
    print(f"Ans: {ans}")

    for col in range(ans_size):
        U_inv[row, 11 - ans_size + col] = ans[col]

print(U_inv)

flag_mat = U_inv * E - pk
print(flag_mat)

suffix = ""
for k in range(5, 24):
    i, j = 5*k // 11, 5*k % 11
    suffix += alphabet[flag_mat[i, j]]

assert len(suffix) == 19
print(suffix)


# First three bytes free
# Next two bytes has 71 possibilities
possibilities = []

# Brute-force
flag_mark[1, 4] = 0

for first_char in range(p):
    row = 1
    ans_size = 10

    count = 0
    for col in range(11):
        if flag_mark[row, col] == 1:
            continue
        count += 1

    left = zero_matrix(GF(p), ans_size, count)
    right = zero_vector(GF(p), count)

    count = 0
    for col in range(11):
        if flag_mark[row, col] == 1:
            continue
        right[count] = pk[row, col]
        if col == 4:
            # Guess this location
            right[count] += first_char
        for y in range(ans_size):
            left[y, count] = E[11 - ans_size + y, col]
        count += 1

    print(f"Row: {row}")
    print(f"Left:\n{left}")
    print(f"Right:\n{right}")

    ans = left.solve_left(right)
    print(f"Ans: {ans}")

    for col in range(ans_size):
        U_inv[row, 11 - ans_size + col] = ans[col]

    flag_mat = U_inv * E - pk
    possibilities.append(alphabet[flag_mat[1, 4]] + alphabet[flag_mat[1, 9]])

print(possibilities)

for prefix in itertools.product(alphabet, repeat=3):
    for mid in possibilities:
        s = prefix[0] + prefix[1] + prefix[2] + mid + suffix
        if sha256(s.encode()).hexdigest() == '95cb911a467482cc0f879861532e9ec7680b0846b48a9de25fb13b01c583d9f8':
            print("flag{" + s + "}")
            exit()
