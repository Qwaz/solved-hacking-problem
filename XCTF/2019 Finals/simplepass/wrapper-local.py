#!/bin/python -u
# coding=utf-8

import os
import signal
import tempfile
import base64
import sys

passso_path = "./SimplePass.so"
def handler(signum, frame):
    print 'Times up! Exiting...'
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(10)
    try:
        #print(base64.b64encode("12312412412"))
        with open('attack.bc', 'rb') as f:
            inputs = f.read()

        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'wb') as tmp:
                # do stuff with temp file
                size = len(inputs)
                cur_idx = 0
                while( cur_idx < size):
                    tmp.write(inputs[cur_idx])
                    cur_idx += 1
            os.system("opt-8 -load %s -SimplePass %s " % (passso_path, path))
            #os.system("cat %s 2>/dev/null" % (path))
            #print(path)
            #raw_input()
            print("Bye~~")
        finally:
            os.remove(path)
    except:
        print("FUCK")
        exit(0)
