from binascii import hexlify, unhexlify
import hashlib

from pwn import *
import nacl.secret


def write_bin(p, data):
    p.sendline(hexlify(data))


def read_bin(p):
    return unhexlify(p.readline().strip())


def int_to_bytes(num):
    s = '%064x' % num
    return unhexlify(s)[::-1]

P = 2 ** 255 - 19
N = (2 ** 252) + 27742317777372353535851937790883648493L

order = list(map(unhexlify, [
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '0100000000000000000000000000000000000000000000000000000000000000',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
    '0000000000000000000000000000000000000000000000000000000000000000',
]))

boxes = []

for key in order:
    m = hashlib.sha256()
    m.update("curve25519-shared:" + key)
    boxes.append(nacl.secret.SecretBox(m.digest()))
    boxes.append(nacl.secret.SecretBox(key))

boxes.append(nacl.secret.SecretBox(int_to_bytes(P)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(P-1)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(P+1)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(1)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(N)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(N-1)))
boxes.append(nacl.secret.SecretBox(int_to_bytes(N+1)))


pk_raw = order[0]

server = remote('mitm.ctfcompetition.com', 1337)
server.sendline('s')

client = remote('mitm.ctfcompetition.com', 1337)
client.sendline('c')

# handshake
server_public = read_bin(server)
server_nonce = read_bin(server)

client_public = read_bin(client)
client_nonce = read_bin(client)

write_bin(server, pk_raw)
write_bin(server, client_nonce)

write_bin(client, pk_raw)
write_bin(client, server_nonce)

server_proof = read_bin(server)
client_proof = read_bin(client)

write_bin(server, client_proof)
write_bin(client, server_proof)

client.close()
auth_msg = server.recvline().strip()
assert 'Error' not in auth_msg

# find shared key
print auth_msg
auth_msg = unhexlify(auth_msg)
print len(auth_msg)

box = nacl.secret.SecretBox('\x00'*32)
c = box.encrypt('AUTHENTICATED')
print len(c)

for box in boxes:
    try:
        if box.decrypt(auth_msg) == 'AUTHENTICATED':
            valid_box = box
            break
        print 'yay'
    except Exception as e:
        print e

write_bin(server, valid_box.encrypt('getflag'))
print valid_box.decrypt(read_bin(server))
