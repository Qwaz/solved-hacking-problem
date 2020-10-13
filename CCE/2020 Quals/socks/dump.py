from pwn import *
from base64 import b64decode
from binascii import unhexlify
import itertools
import pickle

# common stuffs
'''
[*] This is packet sniffer

head=b"CCE2020_"
randstr=''.join(random.choice(string.ascii_letters+string.digits) for _ in range(4))
encoded_string = head+randstr.encode()
hexdigest = hashlib.sha256(encoded_string).hexdigest()

sha256('CCE2020_XXXX') = 3b84c226b62bc49d447c004d18eddc2adfa8d04f199b540148efea912d087cc8

XXXX =  ?

>>>
'''

if os.path.exists("pickle"):
    with open("pickle", "rb") as f:
        hash_dict = pickle.load(f)
else:
    hash_dict = {}
    cnt = 0
    for s in itertools.product(string.ascii_letters + string.digits, repeat=4):
        s = ''.join(s).encode()
        result = hashlib.sha256(b"CCE2020_" + s).digest()
        hash_dict[result] = s
        cnt += 1
        if (cnt & 8191) == 0:
            print("Current: " + str(cnt))
        
    with open("pickle", "wb") as f:
        pickle.dump(hash_dict, f)

while True:
    con = remote('13.124.52.90', 11111)

    leak = con.recvuntil('>>>')
    target = unhexlify(leak.strip().split(b') = ')[1].split()[0])
    con.sendline(hash_dict[target])

    con.recvuntil('and printed.')
    con.sendline('a')

    dat = con.recvall()
    dat = b64decode(dat.strip())
    hashcode = hashlib.sha256(dat).hexdigest()
    with open('sniff/' + hashcode, 'wb') as f:
        f.write(dat)

    con.close()
    print("Packet {} received".format(hashcode[:12]))
