from pwn import *
import hashlib
import binascii
import textwrap
import random

def binary_string(s):
	return bin(int(binascii.hexlify(s),16)).lstrip("0b")

def te(s):
	p = 1 << 7
	return s + "0" * (p-len(s)%p)

def wrap64(s):
	return textwrap.wrap(s, 64) #64

def wrap16(s):
	return textwrap.wrap(s, 16) #16

def ti(l):
	return int(l,2)

def tr(x,y):
	return (x<< y) or (x >> (16-y));

def th(x):
	return "{0:#0{1}x}".format(x,8)

def tp(x,y):
	s = th(x) + th(y)
	s = s.replace("0x","")
	return s

def myhash(text):

	b = binary_string(text)

	p = te(b)

	bl = wrap64(p)

	t11 = 3
	q2 = 5

	tu = [ y**2 for y in range(16)]
	to = [2, 7, 8, 2, 5, 3, 7, 8, 9, 4, 11, 13, 5, 8, 14, 15]

	for i in bl:
		t1 = t11
		t2 = q2

		tl = wrap16(i)
		tq = map(ti, tl)

		for j in range(16):
			if(j >= 12 ):
				tz = (tq[0] & tq[1]) | ~tq[2]
			elif(j >= 8):
				tz = (tq[3] | tq[2])
			elif(j >= 4):
				tz = (~tq[2] & tq[0]) & (tq[1] | ~tq[0])
			elif(j >= 0):
				tz = (tq[0] | ~tq[2]) | tq[1]
			else:
				pass

			t1 = t1 + tr(tz + tu[j] + tq[j%(16>>2)],to[j])
			t2 = t1 + tr(t2,to[j]) %t1

		t11 += t1
		q2 += t2

	t11 = t11 % 0xFF # Should be 0xFFFFFFFF, right?
	q2 = q2 % 0xFF # Same here... 0xFFFFFFFF

	return tp(t11,q2)

p = remote('188.166.133.53', 10009)

p.recvuntil('It has ')
prefix = p.recvn(8)
log.info('prefix is %s' % prefix)

now = 0
while 1:
	cand = prefix + '%07x' % now
	m = hashlib.sha1()
	m.update(cand)
	h = m.digest().encode('hex')
	if h[-4:] == '0000':
		log.info('string is %s' % cand)
		log.info('hash is %s' % h)
		break
	now += 1

p.sendline(cand)

now = 0
while 1:
	cand = ''
	for i in range(18):
		cand += random.choice('0123456789abcdefghijklmnopqrstuvwxyz')
	h = myhash(cand)
	log.info('string %s - hash %s' % (cand, h))
	if h == '00006800007d':
		break
	now += 1

log.info(cand)
log.info(myhash(cand))
p.interactive()

