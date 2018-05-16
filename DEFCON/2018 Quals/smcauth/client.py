from pwn import *
from Crypto.Cipher import AES

import binascii
import re
import socket
import subprocess
import time

PORT = 9988
AUTH_SECRET = '00' * 16
R = 1234568790
E = 65537
CIRCUIT_FILE = './smcauth_syn.v'

AUTH_ARG = [
    './smcauth', 'auth', '--netlist', CIRCUIT_FILE,
    '-v', '127.0.0.1:%d' % PORT,
    '--secret', AUTH_SECRET
]

def recv_socket(socket, byte):
    current = ''
    while len(current) < byte:
        chunk = socket.recv(byte - len(current))
        assert chunk != ''
        current += chunk
    return current

def send_socket(socket, msg):
    total = 0
    while total < len(msg):
        sent = socket.send(msg[total:])
        assert sent != 0
        total += sent

def int_to_str(num, numbytes):
    return binascii.unhexlify('%0{}x'.format(numbytes * 2) % num)

def str_to_int(s):
    return int(binascii.hexlify(s), 16)

p = remote('e65d20aa.quals2018.oooverflow.io', 8080)

# Solve PoW
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('127.0.0.1', PORT))

proc = subprocess.Popen(AUTH_ARG)

serversocket.listen(5)
(clientsocket, address) = serversocket.accept()

pow_request = recv_socket(clientsocket, 20)

p.send(pow_request)
pow_query = p.recvn(88)

send_socket(clientsocket, pow_query)

pow_answer = recv_socket(clientsocket, 52)
client_id = pow_answer[28:44]
p.send(pow_answer)

clientsocket.close()
serversocket.close()

time.sleep(1)

proc.kill()

# Receive Circuit Data
p.recvn(8)
content_len = u64(p.recvn(8), endian='big')

server_label = []
p.recvn(16)
for i in range(256):
    server_label.append(str_to_int(p.recvn(0x20)))

num_circuit = u64(p.recvn(8))
log.info('number of circuit: %d' % num_circuit)

garbled_circuit = []
for i in range(num_circuit):
    num_segment = u64(p.recvn(8))
    assert num_segment == 4
    circuit_table = []
    for j in range(num_segment):
        segment_len = u64(p.recvn(8))
        assert segment_len == 0x30
        circuit_table.append(p.recvn(segment_len))
    garbled_circuit.append(circuit_table)

# RSA
segment_len = u64(p.recvn(8))
assert segment_len == 0x40
rsa_n = str_to_int(p.recvn(segment_len))
log.info('RSA N: %080x' % rsa_n)

assert u64(p.recvn(8)) == 3
assert u32(p.recvn(4)) == 65537
assert u32(p.recvn(4)) == 1
p.recvn(3)

# random value for OT
OT_random = []

for i in range(256):
    local_random = []
    for j in range(2):
        segment_len = u64(p.recvn(8))
        local_random.append(str_to_int(p.recvn(segment_len)))
    OT_random.append(local_random)

packet_cnt = 2

def perform_ot(v):
    global packet_cnt
    payload = p32(2) + p64(16) + client_id + p64(256)

    label = []

    # send author label query
    for i in range(256):
        payload += p64(0x40)
        payload += int_to_str((OT_random[i][v] + pow(R, E, rsa_n))% rsa_n, 0x40)

    payload = p64(packet_cnt, endian='big') + p64(len(payload), endian='big') + payload
    p.send(payload)

    # recv OT result
    assert u64(p.recvn(8), endian='big') == packet_cnt
    content_len = u64(p.recvn(8), endian='big')

    p.recvn(16)

    for i in range(256):
        ot = []

        segment_len = u64(p.recvn(8))
        ot.append(str_to_int(p.recvn(segment_len)))

        segment_len = u64(p.recvn(8))
        ot.append(str_to_int(p.recvn(segment_len)))

        label.append((ot[v] - R + rsa_n) % rsa_n)

    packet_cnt += 1
    return label

client_label = (perform_ot(0), perform_ot(1))

p.close()

# parse circuit
with open(CIRCUIT_FILE) as f:
    circuit_content = f.read()

circuit_lines = circuit_content.split('\n')

def next_line():
    global circuit_lines
    ret = circuit_lines[0]
    circuit_lines = circuit_lines[1:]
    return ret

HEAD_PATTERN = re.compile(r'(\S+) +(\S+) +\($')
BODY_PATTERN = re.compile(r'\.[ABZ]\((\S+)\),?')

circuits = []

while len(circuit_lines):
    current_line = next_line()
    match_result = HEAD_PATTERN.search(current_line)
    if match_result is not None:
        circuits.append({
            'type': match_result.group(1),
            'name': match_result.group(2),
            'in1': BODY_PATTERN.search(next_line()).group(1),
            'in2': BODY_PATTERN.search(next_line()).group(1),
            'out': BODY_PATTERN.search(next_line()).group(1)
        })

print 'parsed %d circuits' % len(circuits)
assert num_circuit == len(circuits)

# garbled calculation
wires = {}

def add_state(wire, label):
    if wire not in wires:
        wires[wire] = []
    if label not in wires[wire]:
        wires[wire].append(label)

def output_label(in1, in2, garbled_table):
    crypto = AES.new(int_to_str(in1 ^ in2, 0x20), AES.MODE_ECB)
    for data in garbled_table:
        dec = crypto.decrypt(data)
        if dec.endswith('\x10' * 16):
            return str_to_int(dec[:-16])
    raise ValueError('invalid label input')

for i in range(256):
    add_state('g_input[%d]'% i, server_label[i])
    add_state('e_input[%d]'% i, client_label[0][i])
    add_state('e_input[%d]'% i, client_label[1][i])

f = open('SMT', 'w')

for i in range(num_circuit):
    in1_name = circuits[i]['in1']
    in2_name = circuits[i]['in2']
    out_name = circuits[i]['out']
    type_name = circuits[i]['type']

    f.write('%s %s %s %s\n' % (type_name, in1_name, in2_name, out_name))

    for in1 in wires[in1_name]:
        for in2 in wires[in2_name]:
            out_label = output_label(in1, in2, garbled_circuit[i])
            add_state(out_name, out_label)
            f.write('%d %d = %d\n' % (
                wires[in1_name].index(in1),
                wires[in2_name].index(in2),
                wires[out_name].index(out_label)
            ))
    f.write('\n')
