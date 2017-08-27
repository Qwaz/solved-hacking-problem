import requests

api_key = 'aaca14463ad73872670c933a647bdf62c249d378ef8fc3b713129f08e38c3f33'


def encrypt(msg):
    content = requests.get('http://iem.eatpwnnosleep.com/encrypt/' + api_key + '-%d' % msg).text
    return int(content)

check = {}
candidates = []

for i in range(2**24):
    if i & 0xff == 0:
        print i
    e = encrypt(i)
    key = i ^ e
    if key in check:
        candidates.append(e ^ check[key])
        print 'key_candidates: {}'.format(candidates)
    check[key] = i
