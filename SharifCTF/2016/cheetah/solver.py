from PIL import Image

im = Image.open("AsianCheetah1.png")

x = 0
y = 0

def next():
    global x, y
    if x == im.width - 1:
        x = -1
        y += 1
    x += 1
    if y == im.height:
        return False
    return True

count = 0
now = 0
decrypt = ''

while True:
    now = now * 2 + (im.getpixel((x, y))[2] & 1)
    count += 1
    if count == 8:
        decrypt += chr(now)
        now = 0
        count = 0
    if not next():
        break

print(decrypt)
