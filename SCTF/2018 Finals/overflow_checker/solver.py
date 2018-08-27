import signal
import subprocess
import os
from pwn import *

DEVNULL = open(os.devnull, 'wb')

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

signal.signal(signal.SIGALRM, alarm_handler)

p = remote('overflow.eatpwnnosleep.com', 32548)

for i in range(100):
    print 'Stage %d' % i
    p.recvuntil('try\n')
    program = p.recvuntil('(y : safe, n : overflow) > \n', drop=True)
    with open('input', 'w') as f:
        f.write(program)

    signal.alarm(4)
    try:
        output = subprocess.check_output(['overflow_checker/target/release/overflow_checker.exe', 'input'], stderr=DEVNULL)
        signal.alarm(0)
    except Alarm:
        print 'timeout'
        output = 'n\n'
    print output
    p.send(output)
    if 'good' not in p.recvline():
        print 'fail...'

p.interactive()
