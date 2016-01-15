from pwn import *
from fractions import gcd

p = process('./server.py')

f = open('admin', 'r')
payload = f.read()
f.close()

p.send(payload)

def long_to_str(num):
	s = "%x" % num
	if len(s) % 2:
		s = '0' + s
	return s.decode('hex')

def str_to_long(str):
	return long(str.encode('hex'), 16)

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def guess(num):
	p.sendline('2')
	p.sendline(long_to_str(num))
	p.recvuntil('icecream! (')
	r = eval(p.recvline()[0:-3])
	r = str_to_long(r)
	print "guess %d - get %d" % (num, r)
	return r

a = guess(2)
b = guess(4)
c = guess(8)
d = guess(16)

n = gcd(gcd(a**2 - b, a**3 - c), a**4 - d)
print "n is %d" % n

aa = modinv(a, n)
print "modular inverse of a - %d" % aa

FLAG2 = guess(2 * str_to_long("FLAG"))
payload = FLAG2 * aa % n

p.sendline('1')
p.sendline(long_to_str(payload))
print p.recvline()

