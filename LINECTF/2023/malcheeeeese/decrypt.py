import binascii
import os

from pwn import *


def leak_ct():
    con = remote("34.85.9.81", 13000)
    con.recvuntil(b"Leaked Token:")

    hex_token = con.recvline().strip()
    assert hex_token[:24] == b"424b734a38625a507633413d"

    ct = binascii.unhexlify(hex_token[24:])
    con.close()

    return ct


if os.path.exists("pickle"):
    with open("pickle", "rb") as f:
        observed_set = pickle.load(f)
else:
    observed_set = [set() for _ in range(124)]

done = all(map(lambda idx: len(observed_set[idx]) == 64, range(16, 120)))

# Enable to fill in the set
if not done:
    for _ in range(300):
        ct = leak_ct()
        for i, c in enumerate(ct):
            observed_set[i].add(c)

    with open("pickle", "wb") as f:
        pickle.dump(observed_set, f)

known_aes = bytearray()

expected_set = set(
    (string.ascii_lowercase + string.ascii_uppercase + string.digits + "+/").encode()
)

for idx in range(16, 120):
    observed = observed_set[idx]
    print(idx, len(observed))

    for t in range(256):
        test_set = set([t ^ c for c in observed])
        if test_set == expected_set:
            known_aes.append(t)
            print("Found: " + binascii.hexlify(known_aes).decode())
            break

    assert(len(known_aes) == idx - 15)

for idx in range(120, 124):
    observed = observed_set[idx]
    print(idx, len(observed))

    expected_set = {
        120: set(b"ABCD"),
        121: set(b"AQgw"),
        122: set(b"="),
        123: set(b"="),
    }

    for t in range(256):
        test_set = set([t ^ c for c in observed])
        if test_set == expected_set[idx]:
            known_aes.append(t)
            print("Found: " + binascii.hexlify(known_aes).decode())
            break

    assert(len(known_aes) == idx - 15)
