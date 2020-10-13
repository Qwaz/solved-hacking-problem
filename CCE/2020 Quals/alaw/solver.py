from pwn import *

payload = b""
payload += p64(0x0F0EB4E43A3C7207)
payload += p64(0x4350120B4A02CB24)
payload += p64(0x4302CB242225435E)
payload += p64(0x222546544306105E)
payload += p64(0x4406410B435CCB24)
payload += p64(0x4A5DCB2422251609)
payload += p64(0x222512091054425F)
payload += p64(0x405441081107CB24)
payload += p64(0x5B0E2D392225085D)
payload += p64(0xB52C2B5118617C37)
payload += p64(0x00617C928D9B8CAA)

payload = payload[:87]

def check_offset(offset):
    key = []
    for i in range(4):
        key.append(payload[offset + i] ^ b"cce2"[i])
    return [key[(i - offset) % 4] for i in range(4)]


def decode_xor(pair):
    i, b = pair
    return bytes((b ^ key[i % 4],))

context.arch = 'amd64'

for offset in range(83):
    print(f"Offset: {offset}")

    key = check_offset(offset)
    decoded = b"".join(map(decode_xor, enumerate(payload)))
    if b"020{" in decoded:
        print(hexdump(decoded))

        disassembled = disasm(decoded)
        print(disassembled)

key = check_offset(58)

decoded = b"".join(map(decode_xor, enumerate(payload)))
disassembled = disasm(decoded)

filename = make_elf(decoded, extract=False)
p = process(filename)
print(p.recvall().decode())
