target = open('flag.zip', 'wb')

for i in range(289):
    t = open('nRixqtv0tfVYxKAZbaFZ(%d)' % i, 'rb')
    target.write(t.read()[:-1] if i < 288 else t.read())
target.close()
