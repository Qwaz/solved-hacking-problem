#!/usr/bin/python
import random, os, sys, time
from ctypes import CDLL, c_char_p
from threading import Timer
libc = CDLL('libc.so.6')
flag = CDLL('./libflag.so')

TIME = 10
class MyTimer():
	timer=None
	def __init__(self):
		self.timer = Timer(TIME, self.dispatch, args=[])
		self.timer.start()
	def dispatch(self):
		print 'time expired! bye!'
		sys.stdout.flush()
		os._exit(0)
		
print '----------------------------------------------------'
print '-  Welcome to pwnable.kr christmas scavanger hunt  -'
print '----------------------------------------------------'
print ''
print 'I\'ve hidden the secret flag for kids somewhere inside'
print 'memory to host a scavanger hunt for christmas party.'
print 'Please do not ruin this party before December 25th.'
print ''
print '                                       - From. santa'
print '----------------------------------------------------'
print ''
sys.stdout.flush()

if random.randrange(10)==0:
	os.system("python gen.py")
	time.sleep(1)

sys.stdout.flush()

MyTimer()
for i in xrange(25):
	sys.stdout.write('addr?:')
	sys.stdout.flush()
	addr = int(raw_input(), 16)
	libc.write(1, c_char_p(addr), 32)

