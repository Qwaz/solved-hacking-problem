from pwn import *

import base64
import hashlib

iv = '2jpmLoSsOlQrqyqE'
welcome_plain = 'Welcome!!' + chr(7)*7

p = remote('52.193.157.19', 9999)

p.recvuntil('XXXX+')
salt = p.recvn(16)
p.recvuntil(' == ')
result = p.recvline().strip()

char_set = string.ascii_letters+string.digits
end = False
for p1 in char_set:
    for p2 in char_set:
        for p3 in char_set:
            for p4 in char_set:
                m = hashlib.sha256()
                m.update(p1+p2+p3+p4+salt)
                if result == m.hexdigest():
                    end = True
                    break
            if end:
                break
        if end:
            break
    if end:
        break

p.recvuntil('XXXX:')
p.sendline(p1+p2+p3+p4)

p.recvuntil('Done!\n')
welcome_byte = base64.b64decode(p.recvline())[16:]


def dummy_pad(pad):
    last_byte = ord(iv[15]) ^ ord(welcome_plain[15])
    return 'Q'*15 + chr(last_byte ^ (pad + 32)) + welcome_byte


def send_block(msg):
    if len(msg) == 16:
        pad_length = 0
    else:
        pad_length = 16 - len(msg) % 16
        msg = msg + 'Q' * pad_length

    b = ''
    for i in range(16):
        b += chr(ord(msg[i]) ^ ord(iv[i]) ^ ord(welcome_plain[i]))
    p.sendline(base64.b64encode(b + welcome_byte + dummy_pad(pad_length)))
    return p.recvline()

# flag is 48 bytes
flag_bytes = base64.b64decode(send_block('get-flag'))[16:]

splitted = []
while len(flag_bytes) > 0:
    splitted.append(flag_bytes[:16])
    flag_bytes = flag_bytes[16:]

prev_block = iv
known_prefix = 'hitcon{'
flag = known_prefix

for b in range(len(splitted)):
    block = splitted[b]

    # decrypt current block
    controlled_prev = ''.join([
        chr(ord(prev_block[i]) ^ ord(known_prefix[i]) ^ ord('get-md5'[i])) for i in range(7)
    ]) + prev_block[7:]
    suffix = ''
    for idx in range(9):
        payload = controlled_prev + block + dummy_pad(8-idx)
        p.sendline(base64.b64encode(payload))
        target = p.recvline()
        found = False
        for t in string.printable:
            md5_result = send_block('get-md5' + suffix + t)

            if md5_result == target:
                found = True
                suffix += t
                flag += t
                break
        if not found:
            # unprintable padding reached
            exit(0)
        print flag

    # decrypt next block prefix
    if b == len(splitted)-1:
        break

    next_block = splitted[b+1]
    next_prefix = ''
    controlled_prev = ''.join([
        chr(ord(prev_block[i]) ^ ord((known_prefix+suffix)[i]) ^ ord((' '*9 + 'get-md5')[i])) for i in range(16)
    ])
    for idx in range(7):
        payload = controlled_prev + block + next_block + dummy_pad(15-idx)
        p.sendline(base64.b64encode(payload))
        target = p.recvline()
        found = False
        for t in string.printable:
            md5_result = send_block('get-md5' + next_prefix + t)

            if md5_result == target:
                found = True
                next_prefix += t
                flag += t
                break
        if not found:
            # unprintable padding reached
            exit(0)
        print flag

    # update level
    prev_block = block
    known_prefix = next_prefix
