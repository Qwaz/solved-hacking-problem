import sys
from subprocess import call

import signal
import os
def handler(signum, frame):
    os._exit(-1)

signal.signal(signal.SIGALRM, handler)
signal.alarm(30)


INPUT_FILE="/share/input"
OUTPUT_PATH="/share/out/"

def just_saying (fname):
    with open(fname) as f:
        lines = f.readlines()
        i=0
        for l in lines:
            i += 1

            if i == 5:
                break

            l = l.strip()

            # Do TTS into mp3 file into output path
            call(["sh","-c",
                "espeak " + " -w " + OUTPUT_PATH + str(i) + ".wav \"" + l + "\""])



def main():
    just_saying(INPUT_FILE)

if __name__ == "__main__":
    main()
