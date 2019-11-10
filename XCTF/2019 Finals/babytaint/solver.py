# xctf{35eedc512678301f582de3176d1fc81c}
payload = ''

for i in range(16):
    payload += 'x%d=["Source"()[%d]];' % (i, i)

payload += 'a=['
payload += ','.join('x%d[0]' % i for i in range(16))
payload += '];"Sink"(a)'

print payload
