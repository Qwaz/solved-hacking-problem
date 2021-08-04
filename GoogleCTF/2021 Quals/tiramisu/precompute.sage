import json

p224 = 0xffffffffffffffffffffffffffffffff000000000000000000000001
a224 = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
b224 = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4

p256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a256 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

gx256 = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
gy256 = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

primes = []
found = []

for x in range(2049, 8192, 2):
    if Integer(x).is_prime():
        primes.append(x)
        found.append(None)

my_b = 0
pi = 1

f = open("params.txt", "w")

while pi < p224:
    my_b += 1
    try:
        curve = EllipticCurve(GF(p224), [a224, my_b])
    except ArithmeticError:
        continue
    order = curve.order()
    print("Trying %d" % my_b)
    for i in range(len(primes)):
        if found[i] is None and order % primes[i] == 0:
            point = curve.gens()[0] * (order // primes[i])

            xx = crt(Integer(point[0]), gx256, p224, p256)
            yy = crt(Integer(point[1]), gy256, p224, p256)

            p = curve(Integer(xx % p224), Integer(yy % p224))

            pi *= primes[i]
            print("Found %d" % primes[i])
            print("pi %d" % pi)
            print("p224 %d" % p224)

            found[i] = {
                "order": int(primes[i]),
                "my_b": int(my_b),
                "x": int(xx),
                "y": int(yy),
            }

            f.write(json.dumps(found[i]))
            f.write("\n")
            f.flush()
