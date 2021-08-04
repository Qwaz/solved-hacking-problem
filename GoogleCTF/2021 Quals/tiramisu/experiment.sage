p224 = 0xffffffffffffffffffffffffffffffff000000000000000000000001
a224 = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
b224 = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4

p256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a256 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

gx256 = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
gy256 = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

my_b = 123
x = 54321
y = Integer(mod(x^3 + a224 * x + my_b, p224).sqrt())

assert y^2 % p224 == (x^3 + a224 * x + my_b) % p224

xx = crt(x, gx256, p224, p256)
yy = crt(y, gy256, p224, p256)

assert yy^2 % p256 == (xx^3 + a256 * xx + b256) % p256
assert yy^2 % p224 == (xx^3 + a224 * xx + my_b) % p224
