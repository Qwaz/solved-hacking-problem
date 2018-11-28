import os
from pwn import *

while True:
    p = remote('auth.ctfcompetition.com', 1337)

    p.recvuntil('graph {\n')

    v = 0
    e = 0
    labels = []
    edges = []

    while True:
        l = p.recvline().strip()

        if '[label="' in l:
            assert l[:l.index(' ')].strip() == str(v)
            labels.append(int(l[l.index('[label="') + 8:l.index('"]')]))
            v += 1
        elif '--' in l:
            index = l.index(' -- ')
            v1 = int(l[:index])
            v2 = int(l[index+4:])
            l1 = labels[v1]
            l2 = labels[v2]
            assert abs(l1 - l2) == 1 or abs(l1 - l2) == v
            edges.append((v1, v2))
            e += 1
        elif '}' in l:
            break

    data = '%d %d\n%s\n%s' % (v, e, '\n'.join(map(str, labels)), '\n'.join(map(lambda x: '%d %d' % (x[0], x[1]), edges)))
    with open('input', 'w') as f:
        f.write(data)

    os.system('./algorithm < input > output')
    with open('output') as f:
        payload = f.read()

    print payload
    if "OK" in payload:
        p.send(payload[payload.index('\n') + 1:])
        p.interactive()
        exit(0)

    p.close()
