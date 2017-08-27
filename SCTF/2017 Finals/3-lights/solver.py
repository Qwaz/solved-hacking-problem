import json
import re
import subprocess

from pwn import *
from PIL import Image

p = remote('3-lights.eatpwnnosleep.com', 22341)

p.recvuntil('apikey: ')
p.sendline('aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33')

g = log.progress('Stage ')
for i in range(100):
    g.status('%d / 100' % i)
    p.recvuntil(')\n')
    board = ''.join([p.recvline() for i in range(45)])
    with open('input', 'w') as f:
        f.write(board)
    result = subprocess.check_output('./qr_reverse < input', shell=True)
    s = result.split()

    image = Image.new('RGB', (45+10, 45+10), color=(255, 255, 255))

    for y in range(45):
        for x in range(45):
            image.putpixel((x+5, y+5), (0, 0, 0) if s[y][x] == '1' else (255, 255, 255))

    image.save('qr.png')

    result = subprocess.check_output(['zbarimg', 'qr.png'])
    data = result[result.index('QR-Code:')+8:].strip()

    p.recvuntil('answer: ')
    p.sendline(data)
g.success('all solved')

print p.recvall()
