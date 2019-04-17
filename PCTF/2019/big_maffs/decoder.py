from binascii import hexlify, unhexlify


xor1 = 8369635966715117454557969064641796484983418770552917

xor2 = unhexlify('05 BB 01 59 6F 06 18 61 3D A0 3A E4 9C E4 E1 E6 73 93 81 F2 10 6B'.replace(' ', ''))
xor2 = int(hexlify(xor2[::-1]), 16)

ans = []
for i in range(22):
    c1 = (xor1 >> (i * 8)) & 0xff
    c2 = (xor2 >> (i * 8)) & 0xff
    ans.append(chr(c1 ^ c2))

print ''.join(ans)
