import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad


def id_pw_validity_check(ID, PW):
    if len(ID) < 20 or len(PW) < 20:
        return False
    if len(set(ID)) < 20 or len(set(PW)) < 20:
        return False
    if ID == PW:
        return False
    return True


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def gf_mult(x, y):
    x = int.from_bytes(x, byteorder="big")
    y = int.from_bytes(y, byteorder="big")

    R = 0xE1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= y
        if y & 1:
            y = (y >> 1) ^ R
        else:
            y >>= 1
    return z.to_bytes(16, byteorder="big")


def gf_pow(x, n):
    # One
    result = b"\x80".ljust(16, b"\x00")
    while n > 0:
        if n & 1:
            result = gf_mult(result, x)
        x = gf_mult(x, x)
        n >>= 1
    return result


def gf_inv(x):
    return gf_pow(x, 2**128 - 2)


def ghash(h, a, c):
    u = (len(a) * 8) % (2**64)
    v = (len(c) * 8) % (2**64)
    y = b"\x00" * 16
    for block in [a[i : i + 16] for i in range(0, len(a), 16)]:
        y = gf_mult(xor_bytes(y, block.ljust(16, b"\x00")), h)
    for block in [c[i : i + 16] for i in range(0, len(c), 16)]:
        y = gf_mult(xor_bytes(y, block.ljust(16, b"\x00")), h)
    y = gf_mult(xor_bytes(y, struct.pack(">QQ", u, v)), h)
    return y


def gcm_encrypt(key, iv, plaintext, aad):
    block_size = 16
    cipher = AES.new(key, AES.MODE_ECB)

    assert len(iv) == 12
    j0 = iv + b"\x00\x00\x00\x01"

    h = cipher.encrypt(b"\x00" * block_size)

    counter = Counter.new(32, prefix=j0[:12], initial_value=2, little_endian=False)
    gctr_cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ciphertext = gctr_cipher.encrypt(plaintext)

    s = ghash(h, aad, ciphertext)
    t = cipher.encrypt(j0)
    tag = xor_bytes(s, t)

    return ciphertext, tag


def gcm_decrypt(key, iv, ciphertext, aad, tag):
    block_size = 16
    cipher = AES.new(key, AES.MODE_ECB)

    assert len(iv) == 12
    j0 = iv + b"\x00\x00\x00\x01"

    h = cipher.encrypt(b"\x00" * block_size)

    counter = Counter.new(32, prefix=j0[:12], initial_value=2, little_endian=False)
    gctr_cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    plaintext = gctr_cipher.decrypt(ciphertext)

    s = ghash(h, aad, ciphertext)
    t = cipher.encrypt(j0)
    computed_tag = xor_bytes(s, t)

    if computed_tag != tag:
        raise ValueError("Authentication failed")

    return plaintext


def encrypt_fresh_file(ID, PW, nickname):
    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    key = pw_hash[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    file_data = b""
    file_data += len(nickname).to_bytes(2, "little")
    file_data += nickname.encode()
    file_data += (0).to_bytes(4, "little")  # day
    file_data += (100).to_bytes(4, "little")  # stamina
    file_data += (0).to_bytes(4, "little")  # intelligence
    file_data += (0).to_bytes(4, "little")  # friendship

    file_data = pad(file_data, 16)
    file_data_enc, tag = cipher.encrypt_and_digest(file_data)
    return file_data_enc, tag


def test():
    print("[*] Running tests...")

    def test_gcm_encrypt():
        print("[*] Testing GCM encrypt")

        key = get_random_bytes(16)
        iv = get_random_bytes(12)
        plaintext = b"Hello, World!"
        aad = b"Additional Data"

        # Encrypt using gcm_encrypt function from your code
        ciphertext, tag = gcm_encrypt(key, iv, plaintext, aad)

        # Encrypt using AES.new function from PyCryptodome
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        ciphertext_pycrypto, tag_pycrypto = cipher.encrypt_and_digest(plaintext)

        # Compare the results
        print("      Custom Ciphertext:", ciphertext)
        print("PyCryptodome Ciphertext:", ciphertext_pycrypto)
        print("      Custom Tag:", tag)
        print("PyCryptodome Tag:", tag_pycrypto)
        assert ciphertext == ciphertext_pycrypto
        assert tag == tag_pycrypto

    def test_gf_mult_identity():
        print("[*] Testing gf_mult identity")

        x = get_random_bytes(16)
        one = b"\x80".ljust(16, b"\x00")
        x_times_1 = gf_mult(x, one)
        print(x)
        print(x_times_1)
        assert x == x_times_1

    def test_gf_inv():
        print("[*] Testing gf_inv")

        x = get_random_bytes(16)
        y = get_random_bytes(16)

        z = gf_mult(x, y)
        x_recover = gf_mult(z, gf_inv(y))
        print(x)
        print(x_recover)
        assert x == x_recover

    test_gcm_encrypt()
    test_gf_mult_identity()
    test_gf_inv()

    print("[+] Test done!")
