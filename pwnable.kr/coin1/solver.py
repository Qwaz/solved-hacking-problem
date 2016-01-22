from pwn import *

p = remote('localhost', 9007)
p.recvuntil('Ready?')
p.recvuntil('\n\t\n')

for t in range(100):
    recv = p.recvline()
    print recv

    N, C = recv.split()
    N, C = int(N[2:]), int(C[2:])

    count = 0
    l = 0
    r = N-1
    while l <= r:
        m = (l+r)//2
        expect = (m+1)*10
        p.sendline(' '.join(map(str, range(m+1))))
        if int(p.recvline()) == expect:
            l = m+1
        else:
            r = m-1
        count += 1
    for i in range(C - count):
        p.sendline('0')
        p.recvline()
    p.sendline('%d' % (r+1))
    print p.recvline()
print p.recvline()
print p.recvline()
