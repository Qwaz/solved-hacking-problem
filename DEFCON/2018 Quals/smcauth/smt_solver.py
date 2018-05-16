from z3 import *

import binascii

def int_to_str(num, numbytes):
    return binascii.unhexlify('%0{}x'.format(numbytes * 2) % num)

with open('SMT', 'r') as fin:
    data = fin.read().strip()

data = data.split('\n\n')

# find our input
g_input = [ BoolVal(0) for i in range(256)]
e_input = [ Bool('e_input_%03d' % i) for i in range(256)]
wire_dict = {}

s = Solver()

for table in data:
    table_rows = table.split('\n')
    io = table_rows[0]
    table_rows = table_rows[1:]

    input = io.split()[1:-1]
    output = io.split()[-1]

    input_0 = wire_dict[input[0]] if input[0].startswith('_') else eval(input[0])
    input_1 = wire_dict[input[1]] if input[1].startswith('_') else eval(input[1])

    expression = BoolVal(0)
    for row in table_rows:
        bits = row.split()
        expression = If(
            And(
                input_0 == (True if bits[0] == '1' else False),
                input_1 == (True if bits[1] == '1' else False)
            ),
            True if int(bits[3]) == 1 else False,
            expression)

    wire_dict[output] = expression

s.add(wire_dict['o'] == True)

s.check()
m = s.model()

n = 0
for i in range(256):
    n = (n << 1) + (1 if m[e_input[i]] else 0)

print int_to_str(n, 0x20)
