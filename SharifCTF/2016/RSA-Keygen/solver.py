
from random import randrange
import math
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

primes = get_primes(443)
primes.sort()
del primes[0]

pi = 1
for x in primes:
	pi *= x

x = 2**400 * pi

n = 0xA4E20DDB854955794E7ABF4AE40051C0FC30488C82AB93B7DD046C1CC094A54334C97E84B523BD3F79331EBEAF5249200D729A483D5B8D944D58DF18D2CA9401B1A1A6CDA8A3AC5C234A501794B76886C426FAC35AD9615ADAB5C94B58C03CCFFA891CE0156CBC14255F019617E40DE9124FBBE70D64CD823DCA870FF76B649320927628250D47DB8DFA9BBCE9964CB3FE3D1B69845BD6FA2E6938DDA1F109E5F4E4170C845B976BBD5121107642FC00606208F9BC83322532739BCFEAF706FB2AF985EBD9769C7FBD50ECBF55566BD44FB241F9FD2DE25069AA8C744F0558514F1E9C8E4297A4D4B25D9F2B7494B466C2E6E2834BA68C5C824215018368B4FB
e = 0x10001

ac = n//(x**2)
ad_bc = (n - ac*(x**2))//x
bd = n%x

print 'AC\t%x\n\nAD_BC\t%x\n\nBD\t%x\n' % (ac, ad_bc, bd)

for i in range(2**12):
	a_ = (2**8 - 1) * (2**12) + i
	if ac % a_ == 0:
		a = a_
		c = ac/a
		ta = i
		tc = c % (2**12)
		print 'a: %x / c: %x\nta: %x / tc: %x\n' % (a, c, ta, tc)

# we have a and c!
g = fractions.gcd(a, c)
a_g = a/g
c_g = c/g

ld = ad_bc // a
lb = 0

tt = a * ld + lb * c
while tt != ad_bc:
	if tt < ad_bc:
		lb += 1
	if tt > ad_bc:
		ld -= 1
	tt = a * ld + lb * c

print 'ld: %x / lb: %x' % (ld, lb)

rd = 0
rb = ad_bc // c

tt = a * rd + rb * c
while tt != ad_bc:
	if tt < ad_bc:
		rd += 1
	if tt > ad_bc:
		rb -= 1
	tt = a * rd + rb * c

print 'rd: %x / rb: %x' % (rd, rb)

def getBD(k):
	td = ld - k * (c_g)
	tb = lb + k * (a_g)
	return tb * td

# td - c/g / tb + a/g
l = 0
r = (rb - lb) // (a_g) - 1
while l <= r:
	m = (l + r) >> 1
	if getBD(m) <= getBD(m+1):
		l = m+1
	else:
		r = m-1
mid = l

l = 0
r = mid
while l <= r:
	m = (l + r) >> 1
	if getBD(m) < bd:
		l = m+1
	else:
		r = m-1
print '%x\n%x\n%x\n' % (getBD(l-1)-bd, getBD(l)-bd, getBD(l+1)-bd)
if getBD(l) == bd:
	print 'SOLVED!'
	print 'p: %x\nq: %x\n' % (a*x + b, c*x + d)


l = mid
r = (rb - lb) // (a_g)
while l <= r:
	m = (l + r) >> 1
	if getBD(m) > bd:
		l = m+1
	else:
		r = m-1
print '%x\n%x\n%x\n' % (getBD(l-1)-bd, getBD(l)-bd, getBD(l+1)-bd)
if getBD(l) == bd:
	print 'SOLVED!'
	d = ld - l * (c_g)
	b = lb + l * (a_g)
	print ad_bc == a*d + b*c, bd == b*d, ac == a*c, n == ac * x * x + ad_bc * x + bd

	p = a*x + b
	q = c*x + d
	print 'p: %x\nq: %x\n' % (p, q)

cipher = 0x64A3F710E3CB9B114FD112B45AC4845292D0B1FEE1468147E80FABA3CD56B1206F5C59E5D400A7F20C9BCD5B42C7197A0D07FBBA48BFBDA550C5CAFB562BEC1B1CB301D131E13233F2BD1C80EEB48956FF0BC8DB6AE2CD727FB1DAC62822331B15A6044F825D01D81036DA3CC8A3575165E813051036715CDF5F7865676DC2513AAD08C5113DFFDC4E6B13E6FFCA2FAD1AA6986D3ED9F1896C109F641074DA7DBFE62CCAD3CACE4B80332475FE3C9EC4869FCA31EE2860D45959F8583C2AEC7A00FC2FD63DBF6CBEB1C604D60CF780FE028ED0AD65DC74BC5335F96EE7CEDEA292F76B427E5F402BCC609B39302CD4A51F405C6ACF8B8A7569AAD9A9318F060B
d = modinv(e, (p-1)*(q-1))

m = pow(cipher, d, n)
print "m=%X" % m
print ("%x" % m).decode('hex')
print "bitlength(m)=", len(bin(m))-2
