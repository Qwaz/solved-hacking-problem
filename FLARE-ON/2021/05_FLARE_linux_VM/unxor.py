import glob

with open("empty.broken", "rb") as f:
    xor_bytes = bytearray(f.read())

for name in list(glob.glob("Documents/*.broken")) + ["Documents/.daiquiris.txt.broken"]:
    with open(name, "rb") as f:
        enc = bytearray(f.read())

    out = b""

    for i in range(1024):
        out += bytes((xor_bytes[i] ^ enc[i],))

    new_name = "Fixed/" + name[len("Documents/"):-len(".broken")]
    with open(new_name, "wb") as f:
        f.write(out.rstrip(b"\x00"))
