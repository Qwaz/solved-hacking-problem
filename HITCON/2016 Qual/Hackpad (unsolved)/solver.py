import hashlib
from pwn import *


def remove_leading_zeros(txt):
    if txt.startswith("00"):
        return remove_leading_zeros(txt[2:])
    return txt

md5_list = []
msg_list = []
dict_msg = []
with open("msg_responses", "r") as fin:
    dat = fin.readlines()
    for line in dat[::-1]:
        line = line.strip()
        if line.startswith('md5'):
            md5_list.append(line.split(" = ")[1])
        elif line.startswith('msg'):
            msg_list.append(line.split("=")[1])

p = log.progress("Working")

msg_count = len(md5_list) // 16
for i in range(msg_count):
    plaintext = ""
    p.status("{} / {}: {}".format(i+1, msg_count, plaintext.encode("hex")))

    current_msg = msg_list[i*16]
    log.info("enc {} / plain {}".format(current_msg, plaintext.encode("hex")))

    for j in range(1, 16):
        current_msg = msg_list[i*16 + j]
        for k in range(256):
            if (hashlib.md5(plaintext + chr(k)).hexdigest() == md5_list[i*16 + j]):
                plaintext += chr(k)
                log.info("enc {} / plain {}".format(current_msg, plaintext.encode("hex")))
                dict_msg.append((current_msg, plaintext.encode("hex")))

                delta = ''
                for t in range(16):
                    prev_msg = msg_list[i*16 + j - 1]
                    current_byte = int(current_msg[t*2 : (t+1)*2], 16)
                    prev_byte = int(prev_msg[t*2 : (t+1)*2], 16)
                    delta += '{:>+4x}'.format(current_byte - prev_byte)
                log.info(delta)
                break

to_decode = msg_list[-1]
for ms in dict_msg:
    to_decode = to_decode.replace(remove_leading_zeros(ms[0]), "{" + ms[1] + "}")

log.info(to_decode)
