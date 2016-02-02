from pwn import *
from timeit import default_timer as timer

p = remote('localhost', 9008)

print p.recvuntil('3 sec ... -\n')
p.recvline()

for i in range(100):
	N, C = p.recvline().split()
	N, C = int(N[2:]), int(C[2:])

	t_start = timer()
	arr = ['' for i in range(C)]
	for n in range(N):
		for c in range(C):
			if n & (1 << c):
				arr[c] += str(n)+' '
	for c in range(C):
		p.send(arr[c][:-1] + ('\n' if c == C-1 else '-'))
	t_send = timer()
	print 'client: ' + str(t_send - t_start)

	weights = map(int, p.recvline().split('-'))
	t_receive = timer()
	print 'server: ' + str(t_receive - t_send)

	ans = 0
	for c in range(C):
		if weights[c] % 10 != 0:
			ans |= 1 << c
	p.sendline(str(ans))
	print p.recvline()

print p.recvline()
print p.recvline()

