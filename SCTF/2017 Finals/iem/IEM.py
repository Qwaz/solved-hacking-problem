from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from SCTF import check_user, check_user_auth, FLAG
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
                msg = self.permutation(msg ^ key)
        return msg


class IEM_Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        enc_url = '/encrypt/'
        auth_url = '/auth/'
        if not self.path.startswith(enc_url):
            if self.path.startswith(auth_url):
                url = self.path[len(auth_url):]
                api, auth = url.split('-', 2)
                if check_user_auth(api, auth) and auth == KEY:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(FLAG)
                else:
                    self.send_response(400)
                return
            else:
                self.send_response(400)
                return

        url = self.path[len(enc_url):]
        api, msg = url.split('-', 2)
        try:
            if not check_user(api, msg):
                raise ValueError

            msg = int(msg)
            if not (0 <= msg < 2**24):
                raise ValueError
        except ValueError:
            self.send_response(400)
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(CIPHER.encrypt(msg)))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


if __name__ == '__main__':
    if len(sys.argv) >= 3:
        addr, port = sys.argv[1], int(sys.argv[2])
    else:
        addr, port = '0.0.0.0', 80

    KEY = os.urandom(6).encode('hex')
    keys = [int(KEY, 16) & 0xffffff, int(KEY, 16) >> 24]
    CIPHER = IteratedEvenMansour(keys)

    server = ThreadedHTTPServer((addr, port), IEM_Handler)
    server.serve_forever()
