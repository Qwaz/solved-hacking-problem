import hashlib
import random
import re

alphanumeric = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
while 1:
	cand = ''
	for i in range(16):
		cand += random.choice(alphanumeric)
	m = hashlib.md5()
	m.update(cand)
	h1 = m.hexdigest()
	m = hashlib.md5()
	m.update(h1+'SALT')
	h2 = m.hexdigest()

	result = re.match('0e[0-9]{30}', h2)
	if result:
		break

print cand
print h2
