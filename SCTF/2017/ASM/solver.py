from PIL import Image
import requests

import cStringIO
import json
from Queue import Queue

WHITE_CELL = (255, 255, 255, 255)

DATA = (
    ('+', 854, 47, 52),
    ('*', 826, 39, 51),
    ('-', 229, 22, 10),
    ('0', 1696, 47, 74),
    ('1', 897, 29, 73),
    ('2', 1369, 43, 73),
    ('3', 1459, 46, 73),
    ('4', 1206, 46, 73),
    ('5', 1378, 40, 74),
    ('6', 1492, 47, 74),
    ('7', 1094, 46, 73),
    ('8', 1841, 47, 74),
    ('9', 1502, 47, 74),
)


def bfs(img, check, x, y):
    q = Queue()

    check[y][x] = 1
    q.put((x, y))

    cnt = 0
    min_x = img.width
    max_x = 0
    min_y = img.height
    max_y = 0

    while not q.empty():
        x, y = q.get()
        cnt += 1
        min_x = min(min_x, x)
        max_x = max(max_x, x)
        min_y = min(min_y, y)
        max_y = max(max_y, y)

        for next_xy in ((x+1, y), (x, y+1), (x-1, y), (x, y-1)):
            nx = next_xy[0]
            ny = next_xy[1]
            if 0 <= nx < img.width and 0 <= ny < img.height:
                if not check[ny][nx] and img.getpixel((nx, ny)) != WHITE_CELL:
                    check[ny][nx] = 1
                    q.put((nx, ny))

    return (cnt, min_x, max_x, min_y, max_y)

s = requests.Session()

r = s.post('http://asm.eatpwnnosleep.com/start')
img_url = r.content

while True:
    r = s.get('http://asm.eatpwnnosleep.com'+img_url)
    img_data = cStringIO.StringIO()
    img_data.write(r.content)

    img = Image.open(img_data)

    r_img = Image.new(img.mode, (img.width, img.height), WHITE_CELL)
    g_img = Image.new(img.mode, (img.width, img.height), WHITE_CELL)
    b_img = Image.new(img.mode, (img.width, img.height), WHITE_CELL)

    for y in range(img.height):
        for x in range(img.width):
            pixel = img.getpixel((x, y))
            if pixel[0] > pixel[1]+70 or pixel[0] > pixel[2]+70:
                r_img.putpixel((x, y), (0, 0, 0, 255))
            if pixel[1] > pixel[0]+70 or pixel[1] > pixel[2]+70:
                g_img.putpixel((x, y), (0, 0, 0, 255))
            if pixel[2] > pixel[0]+70 or pixel[2] > pixel[1]+70:
                b_img.putpixel((x, y), (0, 0, 0, 255))

    with open('img.png', 'wb') as f:
        f.write(r.content)

    r_img.save('red.png')
    g_img.save('green.png')
    b_img.save('blue.png')

    question = []

    for current_img in (r_img, g_img, b_img):
        checked = [[0 for x in range(img.width)] for y in range(img.height)]

        for y in range(img.height):
            for x in range(img.width):
                if not checked[y][x] and current_img.getpixel((x, y)) != WHITE_CELL:
                    result = bfs(current_img, checked, x, y)
                    cnt = result[0]
                    width = result[2]-result[1]
                    height = result[4]-result[3]
                    mid_x = (result[1]+result[2])*.5
                    if cnt > 100:
                        for data in DATA:
                            if data[1]-5 <= cnt <= data[1]+5:
                                question.append((mid_x, data[0]))

    qstring = ''.join(map(lambda t: t[1], sorted(question)))

    a = 0
    op = None
    b = 0
    for c in qstring:
        if c in '*+-':
            op = c
        elif op is None:
            a = a*10 + ord(c)-ord('0')
        else:
            b = b*10 + ord(c)-ord('0')

    if op == '*':
        ans = a*b
    elif op == '-':
        ans = a-b
    else:
        ans = a+b

    r = s.post('http://asm.eatpwnnosleep.com/check', data={'ans': ans})
    d = json.loads(r.content)
    if d['flag'] == '':
        print 'Stage %d' % d['stage']
        img_url = d['url']
    else:
        print d['flag']
        break
