import random
import time
import os

while not os.path.isfile('bh'):
	f = open('/tmp/random_padding', 'wb')
	f.write('\x90' * random.getrandbits(12))
	f.close()
	time.sleep(0.1)