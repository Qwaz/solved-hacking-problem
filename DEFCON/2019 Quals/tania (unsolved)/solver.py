from pwn import *

if os.path.exists('data'):
    with open('data', 'rb') as f:
        (m1_save, m2_save) = pickle.load(f)
else:
    m1_save = {}
    m2_save = {}

M1 = "the rules are the rules, no complaints"
M2 = "reyammer can change the rules"

m1_m2 = True
while True:
    p = remote('tania.quals2019.oooverflow.io', 5000)

    p.recvuntil('> ')
    p.sendline('S')
    p.recvuntil('cmd:')
    if m1_m2:
        p.sendline(M1)
    else:
        p.sendline(M2)

    # drop first r and s

    p.recvuntil('> ')
    p.sendline('S')
    p.recvuntil('cmd:')
    if m1_m2:
        p.sendline(M2)
    else:
        p.sendline(M1)

    p.recvuntil('r: ')
    r = int(p.recvline().strip())
    p.recvuntil('s: ')
    s = int(p.recvline().strip())

    p.close()

    if m1_m2:
        m2_save[r] = s
        if r in m1_save:
            break
    else:
        m1_save[r] = s
        if r in m2_save:
            break

    m1_m2 = not m1_m2

    with open('data', 'wb') as f:
        pickle.dump((m1_save, m2_save), f)

    print len(m1_save), len(m2_save)

with open('data', 'wb') as f:
    pickle.dump((m1_save, m2_save), f)

m1_s = m1_save[r]
m2_s = m2_save[r]

print 'r: %d' % r
print 'M1: %s' % M1
print 's1: %d' % m1_s
print 'M2: %s' % M2
print 's2 %d' % m2_s
