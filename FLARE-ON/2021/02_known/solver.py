with open("Files/latin_alphabet.txt.encrypted", "rb") as f:
    enc_alphabet = f.read()[:8]

alphabet = b"abcdefghijklmnopqrstuvwxyz"
alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def ror(num, x):
    assert x < 8
    return ((num & ((1 << x) - 1)) << (8 - x)) | (num >> x)

passwd = ""

for i, b in enumerate(enc_alphabet):
    idx = i % 8
    passwd += chr(ror((alphabet[i] + idx) & 0xFF, idx) ^ b)

# No1Trust
# You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com
print(passwd)