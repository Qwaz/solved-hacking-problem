import hashlib
import json

from yao import evaluate_circuit
from public_data import g_tables


def xor(A, B):
    return bytes(a ^ b for a, b in zip(A, B))


##########################################################


circuit_filename = "circuit.json"
with open(circuit_filename) as json_file:
    circuit = json.load(json_file)


inputs = {
    1: 11693387,
    2: 11338704,
    3: 7371799,
    4: 2815776,
}

evaluation = evaluate_circuit(circuit, g_tables, inputs)
print(evaluation)


##########################################################


msg = "{}:{}:{}:{}".format(inputs[1], inputs[2], inputs[3], inputs[4])
msg = msg.encode('ascii')

m = hashlib.sha512()
m.update(msg)
m.digest()

xor_flag = b'\x90),u\x1b\x1dE:\xa8q\x91}&\xc7\x90\xbb\xce]\xf5\x17\x89\xd7\xfa\x07\x86\x83\xfa\x9b^\xcb\xd77\x00W\xca\xceXD7'

print(xor(m.digest(), xor_flag))
