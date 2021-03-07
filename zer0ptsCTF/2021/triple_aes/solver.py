from pwn import *

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify
from hashlib import md5
import os
import pickle


def aes_with_key(key):
    assert 0 <= key < 2 ** 24
    key_bytes = md5(key.to_bytes(3, "big")).digest()
    return AES.new(key_bytes, mode=AES.MODE_ECB)


# All zero block
ZERO = bytes(AES.block_size)
ZERO_HEX = hexlify(ZERO)

# How many tries
N = 3

print("Populating key3 table...")

PICKLE_FILE = "key3.pickle"
if os.path.exists(PICKLE_FILE):
    with open(PICKLE_FILE, 'rb') as f:
        key3_table = pickle.load(f)
else:
    key3_table = {}

    for key3 in range(2 ** 24):
        # (E3(X) ^ X) -> key3
        aes = aes_with_key(key3)
        key3_table[aes.encrypt(ZERO)] = key3

    with open(PICKLE_FILE, 'wb') as f:
        pickle.dump(key3_table, f)

iv1 = [get_random_bytes(AES.block_size) for _ in range(N)]

print("Collecting cipher pairs from the server...")

con = remote("crypto.ctf.zer0pts.com", 10929)

dec_result = []

for i in range(N):
    con.recvuntil("\n> ")
    con.sendline("2")
    con.recvuntil("your ciphertext: ")
    con.sendline("{}:{}:{}{}".format(
        hexlify(iv1[i]).decode(),
        ZERO_HEX.decode(),
        ZERO_HEX.decode(),
        ZERO_HEX.decode(),
    ))
    con.recvuntil("here's the plaintext(hex): ")

    received = unhexlify(con.recvline().strip())
    assert len(received) == AES.block_size * 2

    dec_result.append((received[:AES.block_size], received[AES.block_size:]))

con.recvuntil("\n> ")
con.sendline("3")
con.recvuntil("here's the encrypted flag: ")
line = con.recvline().strip()
flag_iv1, flag_iv2, flag_cipher = tuple(map(unhexlify, line.split(b":")))


# Check the validity of key1
# Returns key3 if successful, None otherwise
def key3_from_key1(key1):
    aes = aes_with_key(key1)

    key3 = None
    for i in range(N):
        dec = dec_result[i]
        key3_result = strxor(
            strxor(aes.encrypt(dec[0]), aes.encrypt(dec[1])), iv1[i]
        )
        if key3_result not in key3_table:
            return None
        key3_cand = key3_table[key3_result]

        if key3 is None:
            key3 = key3_cand
        elif key3 != key3_cand:
            return None

    return key3

print("Brute forcing key1...")

for key1 in range(2 ** 24):
    key3 = key3_from_key1(key1)
    if key3 is not None:
        break

# We now have valid key1 and key3 at this point
aes3 = aes_with_key(key3)
aes1 = aes_with_key(key1)


def key2_is_valid(key2):
    global aes1, aes3
    aes2 = aes_with_key(key2)

    for i in range(N):
        dec = dec_result[i]
        guess = aes1.decrypt(strxor(aes2.decrypt(aes3.encrypt(ZERO)), iv1[i]))
        if guess != dec[0]:
            return False
    
    return True

print("Brute forcing key2...")

for key2 in range(2 ** 24):
    if key2_is_valid(key2):
        break

def get_ciphers(keys, iv1, iv2):
    return [
        AES.new(keys[0], mode=AES.MODE_ECB),
        AES.new(keys[1], mode=AES.MODE_CBC, iv=iv1),
        AES.new(keys[2], mode=AES.MODE_CFB, iv=iv2, segment_size=8*16),
    ]

def decrypt(keys, c, iv1, iv2) -> bytes:
    assert len(c) % 16 == 0
    ciphers = get_ciphers(keys, iv1, iv2)
    m = c
    for cipher in ciphers[::-1]:
        m = cipher.decrypt(m)
    return m

keys = [
    md5(key1.to_bytes(3, "big")).digest(),
    md5(key2.to_bytes(3, "big")).digest(),
    md5(key3.to_bytes(3, "big")).digest(),
]

print("Decrypting the flag...")

flag_bytes = decrypt(keys, flag_cipher, flag_iv1, flag_iv2)
print(flag_bytes.decode())
