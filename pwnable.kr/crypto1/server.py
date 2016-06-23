#!/usr/bin/python
import xmlrpclib, hashlib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.Cipher import AES
import os, sys

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'

def AES128_CBC(msg):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return DecodeAES(cipher, msg).rstrip(PADDING)

def authenticate(e_packet):
	packet = AES128_CBC(e_packet)

	id = packet.split('-')[0]
	pw = packet.split('-')[1]

	if packet.split('-')[2] != cookie:
		return 0	# request is not originated from expected server

	if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'guest':
		return 1
	if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'admin':
		return 2
	return 0

server = SimpleXMLRPCServer(("localhost", 9100))
print "Listening on port 9100..."
server.register_function(authenticate, "authenticate")
server.serve_forever()
