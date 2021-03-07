from pwn import *

from base64 import b64decode
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

con = remote("crypto.ctf.zer0pts.com", 10130)

con.recvuntil("Encrypted flag: ")
enc_flag = con.recvline().strip()

con.recvuntil("p = ")
p = int(con.recvline().strip())

con.recvuntil("key.bit_length() = ")
key_bits = int(con.recvline().strip())

a = 1234567
b = pow(a, -1, p)
d = p - 1

key = 0
cursor = 1

def find_next_bit(con):
    con.recvuntil("t = ")
    t = int(con.recvline().strip())

    con.recvuntil("a = ")
    con.sendline(str(a))

    con.recvuntil("b = ")
    con.sendline(str(b))

    con.recvuntil("c = ")
    con.sendline(str(t))

    con.recvuntil("d = ")
    con.sendline(str(d))

    con.recvuntil("x = ")
    x = int(con.recvline().strip())

    con.recvuntil("y = ")
    y = int(con.recvline().strip())

    con.recvuntil("z = ")
    z = int(con.recvline().strip())

    # pow(d, r, p) is 1 or p-1
    # since d = -1 mod p
    for drp in (1, p-1):
        for (b0, b1) in ((0, 0), (0, 1), (1, 0), (1, 1)):
            # Requires Python 3.8+
            drp_inv = pow(drp, -1, p)
            tsp = (z * drp_inv) % p
            tsp_inv = pow(tsp, -1, p)

            arp = ((x ^ b0) * tsp_inv) % p
            brp = ((y ^ b1) * tsp_inv) % p

            if (arp * brp) % p == 1:
                return (b0, b1)

    raise ValueError("Not Found")

while key_bits > 0:
    print(f"Remaining bits: {key_bits}")
    b0, b1 = find_next_bit(con)
    key += (b1 * 2 + b0) * cursor
    cursor <<= 2
    key_bits -= 2

# AES decryption with recovered key
enc_flag_bytes = b64decode(enc_flag)

iv = enc_flag_bytes[:AES.block_size]
c = enc_flag_bytes[AES.block_size:]

aes = AES.new(key=long_to_bytes(key), mode=AES.MODE_CBC, iv=iv)
flag = unpad(aes.decrypt(c), AES.block_size)

print(flag)
