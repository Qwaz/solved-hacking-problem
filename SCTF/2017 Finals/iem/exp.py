from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import random
import sys
import os


class IteratedEvenMansour():
    def __init__(self, keys):
        self.keys = keys
        self.rndMap = self.genRndMap('I love Crypto. How about you?')

    def permutation(self, m):
        l, r = m & 0xfff, m >> 12
        for i in range(8):
            l, r = r, self.rndMap[r] ^ l
        return r | (l << 12)

    def genRndMap(self, seed=None, size=4096):
        if seed:
            random.seed(seed)
        return [random.randint(0, 0xfff) for _ in range(size)]

    def encrypt(self, msg):
        for rnd in range(100):
            for key in self.keys:
                print msg
                msg = self.permutation(msg ^ key)
        return msg

seen = {}

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        addr, port = sys.argv[1], int(sys.argv[2])
    else:
        addr, port = '0.0.0.0', 80

    KEY = os.urandom(6).encode('hex')
    keys = [int(KEY, 16) & 0xffffff, int(KEY, 16) >> 24]
    CIPHER = IteratedEvenMansour(keys)

    cnt = 0
    msg = int(os.urandom(3).encode('hex'), 16)
    first_msg = msg
    while msg not in seen:
        cnt += 1
        seen[msg] = cnt
        for key in keys:
            msg = CIPHER.permutation(msg ^ key)

    print first_msg
    print keys
    print seen[msg], cnt
