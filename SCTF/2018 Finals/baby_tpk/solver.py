from base64 import b64decode
from binascii import unhexlify
from Crypto.Cipher import CAST

key = 'samsungctf_TPK'
iv = b64decode('aXZpc2hlcmU=')

data = '''
5C E0 B9 F2 C4 1C 7D 73 68 F7 A5 F6 98 49 BF E1
CF 5D 82 B2 59 D1 41 07 60 75 94 EC 3A D1 35 2B
16 80 D0 C7 39 F8 B1 28 12 F9 6C 78 DE E4 9F BB
'''.replace(' ', '').replace('\n', '')
data = unhexlify(data)

obj = CAST.new(key, CAST.MODE_OFB, iv)
print obj.encrypt(data)
