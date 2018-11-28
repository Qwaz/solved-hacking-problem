import re
from pwn import *
from z3 import *

# download the file source code and replace 'softmagic.c'
# giving debug option would print additional information compared to the original version
# easier solution is to map 'flag.mgc' in memory and convert it as an array of struct
with open('rules') as f:
    rule_arr = f.read().split('================================')

header = 'CTF{'
footer = '}\x00\x00\x00' + '\x00' * 24

s = Solver()

d1 = BitVec('d1', 64)
d2 = BitVec('d2', 64)
d3 = BitVec('d3', 64)

flag = [BitVec('f%d' % i, 8) for i in range(32)]

s.add(d1 ^ d2 ^ d3 == 0)

flag_index = 0
xor_index = 0
d2_index = 0
d3_index = 0
for rule in rule_arr[1:]:
    # offset, get, comparison
    pattern = re.compile(r'\d+: >* (\d+) ([^,]+),([^,]+),[^\]]*\]')
    now = re.findall(pattern, rule)

    if flag_index < 32:
        acc_cond = False

        for i in range(16):
            check = now[1 + i*8]
            cond1 = now[2 + i*8]
            cond2 = now[3 + i*8]

            chr_num = ord('%x' % i)

            assert check[0] == str(4 + flag_index)
            assert check[2] == '=%d' % chr_num

            new_cond = flag[flag_index] == chr_num

            if cond1[0] == '0':
                assert cond1[1].startswith('byte&')
                assert cond1[2] == 'x'
            else:
                assert cond1[0] == '64'
                assert cond1[1].startswith('lequad&')
                assert cond1[2].startswith('=')

                mask1 = int(cond1[1][7:], 16)
                val1 = int(cond1[2][1:])

                new_cond = And(new_cond, d1 & mask1 == val1)

            if cond2[0] == '0':
                assert cond2[1].startswith('byte&')
                assert cond2[2] == 'x'
            else:
                assert cond2[0] == '72'
                assert cond2[1].startswith('lequad&')
                assert cond2[2].startswith('=')

                mask2 = int(cond2[1][7:], 16)
                val2 = int(cond2[2][1:])

                new_cond = And(new_cond, d2 & mask2 == val2)

            acc_cond = Or(acc_cond, new_cond)

        s.add(acc_cond)
        flag_index += 1
    elif xor_index < 64:
        xor_index += 1
    elif d2_index < 8:
        cond = now[1]
        assert cond[0] == str(72 + d2_index)
        assert cond[1] == 'byte&'
        assert cond[2].startswith('=')

        s.add(Extract((d2_index + 1) * 8 - 1, d2_index * 8, d2) == int(cond[2][1:]))
        d2_index += 1
    elif d3_index < 8:
        cond = now[1]
        assert cond[0] == str(80 + d3_index)
        assert cond[1] == 'byte&'
        assert cond[2].startswith('=')

        s.add(Extract((d3_index + 1) * 8 - 1, d3_index * 8, d3) == int(cond[2][1:]))
        d3_index += 1

assert s.check() == sat

m = s.model()
with open('flag.txt', 'wb') as f:
    payload = header + ''.join(map(chr, map(lambda x: m[x].as_long(), flag))) + footer
    payload += p64(m[d1].as_long())
    payload += p64(m[d2].as_long())
    payload += p64(m[d3].as_long())

    f.write(payload)
