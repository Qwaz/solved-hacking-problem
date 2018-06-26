from pwn import *
from not_des import *

# key: e0e0e0e0 f1f1f1f1
# round key: 111111111111111111111111000000000000000000000000

def recurse(rows):
    if len(rows) < 8:
        for row in range(4):
            result = recurse(rows + [row])
            if result[0] == True:
                return result
        return (False, None)
    else:
        input_num = []

        for i in range(8):
            mid = bin(SBOXES[i][rows[i]].index(0))[2:]
            mid = '0'*(4-len(mid)) + mid
            candidate = str(rows[i] // 2) + mid + str(rows[i] % 2)
            if i < 4:
                candidate = ''.join(map(lambda c: '10'[int(c)], candidate))
            input_num.append(candidate)

        for i in range(8):
            if not input_num[i][:2] == input_num[i-1][-2:]:
                return (False, None)

        return (True, ''.join(map(lambda x: x[1:5], input_num)))

result = recurse([])
assert result[0]

after_ip = result[1]*2
before_ip = [after_ip[IP_INV[i] - 1] for i in range(64)]
plaintext = Bits2Str(before_ip)

p = remote('dm-col.ctfcompetition.com', 1337)

p.send('\x00' * 8)
p.send('plusqwaz')

p.send('\x01' * 8)
p.send('plusqwaz')

p.send('\xe0' * 4 + '\xf1' * 4)
p.send(plaintext)

p.interactive()
