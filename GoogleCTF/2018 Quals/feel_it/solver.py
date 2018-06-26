import binascii

# https://en.wikipedia.org/wiki/International_uniformity_of_braille_alphabets
target = '6a 07 11 1b 0a 1e 48 0e 13 11 07 07 00 18 7b 2b 00 49 5e 4b 2a 13 02 19 11 38 01 1d 19 38 0e 12 12 05 3b c0 00 00 00 00 00 00 00 00 00 00 00 00'

dot = [
    0, 3,
    1, 4,
    2, 5,
    6, 7,
]

target = target.replace(' ', '')
target = binascii.unhexlify(target)

for c in target:
    num = ord(c)
    for i in range(8):
        print '.O'[(num >> dot[i]) & 1],
        if i % 2 == 1:
            print ''
    print ''
