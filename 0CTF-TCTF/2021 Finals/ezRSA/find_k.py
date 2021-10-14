TARGET = 154118536863381755324327990994045278493514334577571515646858907141541837890


def f(k, l):
    return 1337 * k ** 4 + 7331 * l ** 3 + 73331 * k ** 2 + 13337 * l ** 2 + 7 * k * l + 2 * k + l

def try_kl(k, l):
    result = f(k, l)
    print(f"Target: {bin(TARGET)}")
    print(f"Result: {bin(result)}")

    if TARGET > result:
        print("Target is bigger")
    else:
        print("result is bigger")

# manually brute-forced ^^
try_kl(
    0b100000010110000110010100101110011000011010001110010100100000,
    0b100000000000000000000000000000000000000000000000000000000000,
)

try_kl(
    0b100000010110000110010100101110011000011010001110010100100000,
    0b1000000000000000000000000000000000000000000000000000000000000 - 1,
)

# last 5 bytes unknown
k_base = 0b100000010110000110010100101110011000011010001110010100100000

for k_low in range(64):
    k = k_base + k_low

    lo = 0b100000000000000000000000000000000000000000000000000000000000
    hi = 0b1000000000000000000000000000000000000000000000000000000000000

    while hi - lo > 1:
        l_try = (lo + hi) >> 1
        result = f(k, l_try)

        if result <= TARGET:
            lo = l_try
        elif result > TARGET:
            hi = l_try

    result = f(k, lo)
    if result == TARGET:
        print(f"k: {k}")
        print(f"l: {lo}")
        exit()
