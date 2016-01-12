import base64
import urllib.parse
import requests

URL = "http://wargame.kr:8080/dun_worry_about_the_vase/main.php"

key1 = "7SWDHbawgDM="
key2 = "kLcd9rHjAU8="

key1 = bytearray(base64.b64decode(key1))
key2 = bytearray(base64.b64decode(key2))

def send():
	cookie_val = urllib.parse.quote_plus(base64.b64encode(key1)+base64.b64encode(key2))
	r = requests.post(URL, cookies=dict(L0g1n=cookie_val))
	return r.text

def success(current, result):
	if current == 0:
		return "invalid user" in result
	else:
		return "padding" not in result

send()

found = bytearray(b'12345678')

for current in range(8):
	for prev in range(current):
		key1[7 - prev] = found[prev] ^ (current+1)
	for bit in range(256):
		if bit % 16 == 0:
			print("trying - %d byte - %d" % (current, bit))
		key1[7 - current] = bit
		result = send()
		if success(current, result):
			found[current] = bit ^ (current+1)
			print("success - %d byte - %d" % (current, bit ^ (current+1)))
			break

print(found)
