import base64
import urllib.parse

inter = b'0\x83\xb3\xc2n\xe6P\x8a'

key1 = "7SWDHbawgDM="
key2 = "kLcd9rHjAU8="

key1 = bytearray(base64.b64decode(key1))
key2 = bytearray(base64.b64decode(key2))

def print_key():
	print(urllib.parse.quote_plus(base64.b64encode(key1) + base64.b64encode(key2)))

for i in range(8):
	print(inter[7-i] ^ key1[i], chr(inter[7-i] ^ key1[i]))

admin = b'admin\x03\x03\x03'
for i in range(8):
	key1[i] = inter[7-i] ^ admin[i]

print_key()
