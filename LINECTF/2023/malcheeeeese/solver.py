import binascii
import json
import os

from pwn import *

con = remote("34.85.9.81", 13000)

con.recvuntil(b"Leaked Token:")
leaked = binascii.unhexlify(con.recvline().strip())
token_sig_ct = leaked[12 + 16 :]


def try_pw_block(pw_block):
    payload = b"424b734a38625a5076334141"
    payload += binascii.hexlify(pw_block)
    payload += (136 * 2 - len(payload)) * b"0"

    con.sendline(payload)
    out = json.loads(con.recvline())

    return out


FIRST_BLOCK = binascii.unhexlify("0ab348a50367dc8e4231315257c2531c")

if not FIRST_BLOCK:
    """
    ZERO_PW is found by running the following code:

    while True:
    pw_block = os.urandom(16)
    out = try_pw_block(pw_block)
    if out["pwd_len"] != -1:
        print(out)
        print(binascii.hexlify(pw))
    """
    ZERO_PW = binascii.unhexlify("76b6f727ecdbe0b28cca15c29ece33b4")
    assert try_pw_block(ZERO_PW)["pwd_len"] == 0

    base64_chars = (
        string.ascii_lowercase + string.ascii_uppercase + string.digits + "+/"
    ).encode()

    expected_set = set(b"=")
    for c in range(256):
        if c not in base64_chars:
            expected_set.add(c)

    cipher = bytearray()

    for idx in range(16):
        print(f"idx: {idx}")
        pw_cipher = bytearray(ZERO_PW)
        observed = set()

        for b in range(256):
            pw_cipher[idx] = b
            if try_pw_block(pw_cipher)["pwd_len"] == 0:
                observed.add(b)

        for t in range(256):
            test_set = set([t ^ c for c in observed])
            if test_set == expected_set:
                cipher.append(t)
                print("Found: " + binascii.hexlify(cipher).decode())
                break

        assert len(cipher) == idx + 1

pw_block = b""
for c, t in zip(FIRST_BLOCK, b"Y2hlZWVlZXNl****"):
    pw_block += bytes([c ^ t])

assert try_pw_block(pw_block)["pwd_error_number"] == 0

SIG_BLOCK_CIPHER = binascii.unhexlify(
    b"899c9a18a7d880e07191b3cf2ecd6239c3c00ecfbce6487e68967d10c1a0a35397b151b4f688a520052b7dec4e14e368259e01dc0fc9c04353773d4bb1888f34f9a8194b12a61eb43f92216ff50090b859e1bfba9d1f248dea7d60a1a2e21a480c311def559507dc61c255db"
)


def xor_block(b):
    return bytes([c ^ t for c, t in zip(b, SIG_BLOCK_CIPHER)])


payload = b"424b734a38625a5076334141"
payload += binascii.hexlify(pw_block)

token_sig_b64 = xor_block(token_sig_ct)
print(token_sig_b64)
token_b64 = token_sig_b64[:20]
sig_b64 = token_sig_b64[20:]
new_sig_dict = {
    ord("A"): b"B",
    ord("Q"): b"R",
    ord("g"): b"h",
    ord("w"): b"x",
}
new_sig_b64 = sig_b64[:-3] + new_sig_dict[sig_b64[-3]] + b"=="

new_token_sig_b64 = token_b64 + new_sig_b64
print(new_token_sig_b64)
new_sig_ct = xor_block(new_token_sig_b64)

payload += binascii.hexlify(new_sig_ct)

con.sendline(payload)
out = json.loads(con.recvline())
print(out)
