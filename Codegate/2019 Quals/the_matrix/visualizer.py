from PIL import Image

with open('main.dump', 'rb') as f:
    content = f.read()

index = 0
content_len = len(content)

PIXEL = 6
WIDTH = 64
assert(content_len % (16 * WIDTH) == 0)
HEIGHT = content_len / (16 * WIDTH)

im = Image.new('L', (PIXEL * 8 * WIDTH, PIXEL * 8 * HEIGHT))


def set_pixel(index, px, py, color):
    im_x = (index % WIDTH) * PIXEL * 8
    im_y = (index / WIDTH) * PIXEL * 8
    for x in range(PIXEL):
        for y in range(PIXEL):
            im.putpixel((im_x + px * PIXEL + x, im_y + py * PIXEL + y), (255, 160, 80, 0)[color])


while (index + 1) * 16 <= content_len:
    line = content[index * 16 : (index + 1) * 16]
    for y in range(8):
        t1 = ord(line[y * 2])
        t2 = ord(line[y * 2 + 1])
        for x in range(8):
            color = ((t2 >> (7-x)) & 1) * 2 + ((t1 >> (7-x)) & 1)
            set_pixel(index, x, y, color)
    index += 1

im.save('dump.png')
