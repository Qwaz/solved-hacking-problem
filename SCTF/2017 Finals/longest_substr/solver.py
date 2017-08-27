import socket
import json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('longest-substr.eatpwnnosleep.com', 9000))

with open('main.c') as f:
    content = f.read()

print content

a = {
    'apikey': 'aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33',
    'probid': 'longest-substr',
    'sourcetype': 'c',
    'code': content,
}

s.send(json.dumps(a))
print s.recv(102400)
