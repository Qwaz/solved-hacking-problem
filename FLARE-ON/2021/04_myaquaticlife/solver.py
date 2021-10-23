import hashlib
import itertools

initial = bytearray([
    0x96, 0x25, 0xA4, 0xA9, 0xA3, 0x96, 0x9A, 0x90, 0x9F, 0xAF, 0xE5, 0x38, 0xF9, 0x81, 0x9E, 0x16,
    0xF9, 0xCB, 0xE4, 0xA4, 0x87, 0x8F, 0x8F, 0xBA, 0xD2, 0x9D, 0xA7, 0xD1, 0xFC, 0xA3, 0xA8,
])

key4_part = [
    "DFWEyEW",
    "PXopvM",
    "BGgsuhn",
]

key2_part = [
    "newaui",
    "HwdwAZ",
    "SLdkv",
]


def test_keys(k4, k2):
    buf = bytearray(initial)

    k4_len = len(k4)
    assert len(k2) == 17

    for i in range(31):
        buf[i] ^= k4[i % k4_len]
        buf[i] = (buf[i] - k2[i % 17]) & 0xff

    print(hashlib.md5(buf).hexdigest(), k4.decode(), k2.decode())
    if hashlib.md5(buf).hexdigest() == "6c5215b12a10e936f8de1e42083ba184":
        print("FOUND!!!")


for k4 in itertools.permutations(key4_part):
    for k2 in itertools.permutations(key2_part):
        test_keys("".join(k4).encode(), "".join(k2).encode())

# 4 3 13
# 11 7 10

# s1gn_my_gu357_b00k@flare-on.com
