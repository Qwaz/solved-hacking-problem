
from random import randrange
import fractions


def get_primes(n):
	numbers = set(range(n, 1, -1))
	primes = []
	while numbers:
		p = numbers.pop()
		primes.append(p)
		numbers.difference_update(set(range(p*2, n+1, p)))
	return primes

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def miller_rabin(n, k):
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


### main #################
primes = get_primes(443)
primes.sort()
del primes[0]
#print primes

pi = 1;
for x in primes:
	pi *= x
print "pi=%X" % pi

while True:
	kp = randrange(1, 2**12) + 2**12 + 2**13 + 2**14 + \
			2**15 + 2**16 + 2**17 + 2**18 + 2**19
	print "kp=%X" % kp

	tp = 0
	while fractions.gcd(tp, pi) != 1:
		print "trying..."
		tp = randrange(1, 2**399);
	print "tp=%X" % tp

	p = kp * pi * 2**400 + tp
	print "p=%X" % p
	print "bitlength(p)=", len(bin(p))-2

	if miller_rabin(p, 40) == True:
		break

while True:
	kq = randrange(1, 2**12) + 2**12 + 2**13 + 2**14 + \
			2**15 + 2**16 + 2**17 + 2**18 + 2**19
	print "kq=%X" % kq

	tq = 0
	while fractions.gcd(tq, pi) != 1:
		print "trying..."
		tq = randrange(1, 2**399);
	print "tq=%X" % tq

	q = kq * pi * 2**400 + tq
	print "q=%X" % q
	print "bitlength(q)=", len(bin(q))-2

	if miller_rabin(q, 40) == True:
		break

print "p=%X" % p
print "q=%X" % q

n = p * q
print "n=%X" % n
print "bitlength(n)=", len(bin(n))-2

e = 2**16 + 1
print "e=%X" % e
#print "bitlength(e)=", len(bin(e))-2

d = modinv(e, (p-1)*(q-1))
print "d=%X" % d
#print "bitlength(d)=", len(bin(d))-2

m = 12354178254918274687189741234123412398461982374619827346981756309845712384198076
print "m=%X" % m
print "bitlength(m)=", len(bin(m))-2

c = pow(m, e, n)
print "c=%X" % c
print "bitlength(c)=", len(bin(c))-2

m2 = pow(c, d, n)
print "m2=%X" % m2
print "bitlength(m2)=", len(bin(m2))-2
