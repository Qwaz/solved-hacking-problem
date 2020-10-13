goal = 3008192072309708


def n2bin(num, bits):
    s = bin(num)[2:]
    return s.rjust(bits, '0')


def enc(msg):
    assert len(msg) == 8

    memory = [None for _ in range(8)]

    idx = 0
    for c in msg:
        memory[idx] = n2bin(c, 7)
        idx = (idx + 5) % 8

    magic = ''.join((memory[0], memory[5], memory[6], memory[2], memory[4], memory[3], memory[7], memory[1]))
    kittens = ''.join((magic[-10:], magic[-42:-22], magic[-22:-10], magic[-56:-42]))

    return kittens

goal_bin = n2bin(goal, 56)
ans = []

for i in range(8):
    probe = b''.join([b'\x7f' if i == j else b'\x00' for j in range(8)])
    probe_result = enc(probe)

    indices = []
    for x in range(56):
        if probe_result[x] == '1':
            indices.append(x)

    for c in range(0x80):
        c_bytes = bytes([c])
        c_msg = b''.join([c_bytes if i == j else b'\x00' for j in range(8)])
        c_result = enc(c_msg)
        if all(map(lambda i: goal_bin[i] == c_result[i], indices)):
            ans.append(c_bytes)
            break

key = b''.join(ans)
print(key.decode())

print(enc(key))
print(goal_bin)

# CTF{W4sTh4tASan1tyCh3ck?}
