from base64 import b64decode
import requests
import string

URL = "http://drinks.teaser.insomnihack.ch"

flag = '||'
# flag = '||G1MME_B33R_PLZ_1M_S0_V3RY_TH1RSTY'

while len(flag) < 35:
    min_len = 1e50
    next = None

    for c in string.ascii_letters + string.digits + '_':
        r = requests.post(URL + "/generateEncryptedVoucher", json={
            'recipientName': flag + c,
            'drink': 'beer',
        })
        s = r.text.split('\n')
        b64 = ''.join(s[s.index(''):-3])
        bin_data = b64decode(b64)
        cand_len = len(bin_data)

        print '%4d - %s' % (cand_len, flag+c)

        if min_len > cand_len:
            min_len = cand_len
            next = [c]
        elif min_len == cand_len:
            next.append(c)

    if len(next) == 1:
        flag = flag + next[0]
        print flag
    else:
        print next
        flag += raw_input()[0]
