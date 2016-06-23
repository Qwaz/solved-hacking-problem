#!/usr/bin/python
from Crypto.Cipher import AES
import base64
import os, sys
import xmlrpclib
rpc = xmlrpclib.ServerProxy("http://localhost:9100/")

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'

# guest / 8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1
def sanitize(arg):
	for c in arg:
		if c not in '1234567890abcdefghijklmnopqrstuvwxyz-_':
			return False
	return True

def AES128_CBC(msg):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return EncodeAES(cipher, msg)

def request_auth(id, pw):
	packet = '{0}-{1}-{2}'.format(id, pw, cookie)
	e_packet = AES128_CBC(packet)
	print 'sending encrypted data ({0})'.format(e_packet)
	sys.stdout.flush()
	return rpc.authenticate(e_packet)

if __name__ == '__main__':
	print '---------------------------------------------------'
	print '-       PWNABLE.KR secure RPC login system        -'
	print '---------------------------------------------------'
	print ''
	print 'Input your ID'
	sys.stdout.flush()
	id = raw_input()
	print 'Input your PW'
	sys.stdout.flush()
	pw = raw_input()

	if sanitize(id) == False or sanitize(pw) == False:
		print 'format error'
		sys.stdout.flush()
		os._exit(0)

	cred = request_auth(id, pw)

	if cred==0 :
		print 'you are not authenticated user'
		sys.stdout.flush()
		os._exit(0)
	if cred==1 :
		print 'hi guest, login as admin'
		sys.stdout.flush()
		os._exit(0)

	print 'hi admin, here is your flag'
	print open('flag').read()
	sys.stdout.flush()
