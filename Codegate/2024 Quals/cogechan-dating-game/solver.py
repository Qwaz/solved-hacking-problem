"""
=== Parameters ===
id_hash = sha256(ID)
pw_hash = sha256(PW)

Block Size = 16

nonce = id_hash[:12]
file_name = id_hash[16:24].hex()
key = pw_hash[:16]

tag = raw_data[-16:]

AEC_GCM decrypt and verify

=== Save file structure ===
2   nickname_len (X)
X   nickname
4   day
4   stamina
4   intelligence
2   friendship

=== Checks ===
* id_pw_validity_check
* Tag
* Padding (PKCS#7)
* Nick name length
"""

import socket
import string

from Crypto.Util.Padding import unpad
from helper import *
from pwnlib.util.iters import mbruteforce

EAT_COMMAND = 1
PWN_COMMAND = 2
SLEEP_COMMAND = 3
DATE_COMMAND = 4
SAVE_COMMAND = 5

LOAD_SUCCESS = 1
LOAD_FAIL = 2

SAVE_SUCCESS = 11
SAVE_FAIL = 12

test()


def new_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("3.35.166.110", 3434))
    except:
        print("[-] failed to connect a server")
        exit(1)

    return sock


# Step 1: Find forgeable tag pair
nickname = b"A" * 14

ID = "TheDuck_1234567890abcdefg"
PW0 = "Qwaz_1234567890abcdefg"
print(f"[*] Initial PW: {PW0}")

assert id_pw_validity_check(ID, PW0), "Invalid ID or PW"

id_hash = hashlib.sha256(ID.encode()).digest()
nonce = id_hash[:12]

key0 = hashlib.sha256(PW0.encode()).digest()[:16]


def enc_counter(counter, cipher):
    return cipher.encrypt(nonce + counter.to_bytes(4, "big"))


def payload_for_key(key1):
    cipher0 = AES.new(key0, AES.MODE_ECB)
    cipher1 = AES.new(key1, AES.MODE_ECB)

    def enc_then_dec(counter):
        return xor_bytes(enc_counter(counter, cipher0), enc_counter(counter, cipher1))

    scratch_buffer_size = 48

    assert scratch_buffer_size % 16 == 0

    block0 = (14).to_bytes(2, "little") + nickname
    block1 = b""
    block1 += (0).to_bytes(4, "little")  # day
    block1 += (100).to_bytes(4, "little")  # stamina
    block1 += (0).to_bytes(4, "little")  # intelligence
    block1 += (0).to_bytes(4, "little")  # friendship

    block_rest = bytearray(scratch_buffer_size)

    pt_block0 = xor_bytes(block0, enc_then_dec(2))
    nickname_len = int.from_bytes(pt_block0[:2], "little")

    if not (30 <= nickname_len and nickname_len + 16 < 30 + scratch_buffer_size):
        return None

    offset = nickname_len - 30
    data_block = (enc_then_dec(4 + (offset // 16)) + enc_then_dec(5 + (offset // 16)))[
        offset % 16 : offset % 16 + 16
    ]
    # Set day, stamina, intelligence, friendship
    for i, target in enumerate([1234, 999, 0xFFFFFFFF, 33]):
        to_xor = target ^ int.from_bytes(data_block[i * 4 : i * 4 + 4], "little")
        block_rest[offset + i * 4 + 0] ^= (to_xor >> 0) & 0xFF
        block_rest[offset + i * 4 + 1] ^= (to_xor >> 8) & 0xFF
        block_rest[offset + i * 4 + 2] ^= (to_xor >> 16) & 0xFF
        block_rest[offset + i * 4 + 3] ^= (to_xor >> 24) & 0xFF

    h0 = cipher0.encrypt(b"\x00" * 16)
    h1 = cipher1.encrypt(b"\x00" * 16)

    end0 = enc_counter(1, cipher0)
    end1 = enc_counter(1, cipher1)

    g0 = b"\x00" * 16
    g1 = b"\x00" * 16

    prefix = block0 + block1 + block_rest
    for block_idx in range(len(prefix) // 16):
        pt_block = prefix[block_idx * 16 : block_idx * 16 + 16]
        ct_block = xor_bytes(pt_block, enc_counter(2 + block_idx, cipher0))

        g0 = gf_mult(xor_bytes(g0, ct_block), h0)
        g1 = gf_mult(xor_bytes(g1, ct_block), h1)

    L = struct.pack(">QQ", 0, (16 * 4 + scratch_buffer_size) * 8)
    P = b"\x10" * 16

    # If the last block's CT is X,
    # (((g0 + X) * h0 + P) * h0 + L) * h0 + end0 == (((g1 + X) * h1 + P) * h1 + L) * h1 + end1
    # X * (h0 * h0 * h0 + h1 * h1 * h1) == end0 + end1 + L * (h0 + h1) + P * (h0 * h0 + h1 * h1) + g0 * h0 * h0 * h0 + g1 * h1 * h1 * h1
    last_block_counter = 2 + len(prefix) // 16

    h0_cube = gf_mult(gf_mult(h0, h0), h0)
    h1_cube = gf_mult(gf_mult(h1, h1), h1)

    x = xor_bytes(end0, end1)
    x = xor_bytes(x, gf_mult(L, xor_bytes(h0, h1)))
    x = xor_bytes(
        x,
        gf_mult(
            xor_bytes(P, enc_counter(last_block_counter + 1, cipher0)),
            xor_bytes(gf_mult(h0, h0), gf_mult(h1, h1)),
        ),
    )
    x = xor_bytes(x, gf_mult(g0, h0_cube))
    x = xor_bytes(x, gf_mult(g1, h1_cube))
    x = gf_mult(x, gf_inv(xor_bytes(h0_cube, h1_cube)))
    last_block = xor_bytes(x, enc_counter(last_block_counter, cipher0))

    ret = prefix + last_block + P

    # Verify (Optional)
    t0 = b"\x00" * 16
    t1 = b"\x00" * 16
    for block_idx in range(len(ret) // 16):
        pt_block = ret[block_idx * 16 : block_idx * 16 + 16]
        ct_block = xor_bytes(pt_block, enc_counter(2 + block_idx, cipher0))

        t0 = gf_mult(xor_bytes(t0, ct_block), h0)
        t1 = gf_mult(xor_bytes(t1, ct_block), h1)

    t0 = gf_mult(xor_bytes(t0, L), h0)
    t1 = gf_mult(xor_bytes(t1, L), h1)

    t0 = xor_bytes(t0, end0)
    t1 = xor_bytes(t1, end1)

    assert t0 == t1

    return ret


def brute(pw_suffix):
    PW1 = PW0 + pw_suffix

    key1 = hashlib.sha256(PW1.encode()).digest()[:16]
    payload = payload_for_key(key1)
    if payload is None:
        return False

    ciphertext, tag = gcm_encrypt(key0, nonce, payload, b"")
    _forged = gcm_decrypt(key1, nonce, ciphertext, b"", tag)

    try:
        cipher = AES.new(key1, AES.MODE_GCM, nonce)
        unpad(cipher.decrypt_and_verify(ciphertext, tag), 16)
    except ValueError:
        return False

    return True


PW1 = PW0 + mbruteforce(brute, string.ascii_lowercase + string.digits, 8)
print(f"[+] Forged PW: {PW1}")

key1 = hashlib.sha256(PW1.encode()).digest()[:16]
payload = payload_for_key(key1)

ciphertext, tag = gcm_encrypt(key0, nonce, payload, b"")

cipher = AES.new(key1, AES.MODE_GCM, nonce)
file = unpad(cipher.decrypt_and_verify(ciphertext, tag), 16)

with open("debug.hex", "wb") as f:
    f.write(file)

nickname_len = int.from_bytes(file[:2], "little")
print(nickname_len)
data = file[2 + nickname_len : 2 + nickname_len + 16]
print(int.from_bytes(data[0:4], "little"))
print(int.from_bytes(data[4:8], "little"))
print(int.from_bytes(data[8:12], "little"))
print(int.from_bytes(data[12:16], "little"))


# Step 2: leave save file with PW0
sock = new_socket()
sock.send(len(ID).to_bytes(2, "little") + ID.encode())
sock.send(len(PW0).to_bytes(2, "little") + PW0.encode())
status = sock.recv(1)

# We assume this is a new game. If not, change `PW` to start a new game.
assert status[0] == LOAD_FAIL, "ID and PW are already used"

sock.send(len(nickname).to_bytes(2, "little") + nickname)

# Save a new game
sock.send(SAVE_COMMAND.to_bytes(1, "little"))
sock.send(len(ciphertext).to_bytes(2, "little") + ciphertext)
sock.send(tag)
status = int.from_bytes(sock.recv(1), "little")
assert status == SAVE_SUCCESS, "Failed to save a new game"
print("[+] New game saved successfully")

sock.close()

print("[*] Success! Now use PW1 as the credential to play the game! (PWN -> DATE)")
# codegate2024{50e64777df2f4663a79e85f7cecdd49fbc7621f612f625734b57a87052c45330b95af4c6ade9a5d9ac490c83473c8ecbde9ba715979346}
