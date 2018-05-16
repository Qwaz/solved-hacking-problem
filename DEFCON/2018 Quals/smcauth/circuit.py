PROLOGUE = '''module smcauth(clk, rst, g_input, e_input, o);
  input clk;
  input [255:0] e_input;
  input [255:0] g_input;
  output o;
  input rst;
'''

EPILOGUE = 'endmodule\n'

OR_CIRCUIT = '''
  OR {} (
    .A({}),
    .B({}),
    .Z({})
  );
'''

AND_CIRCUIT = '''
  ANDN {} (
    .A({}),
    .B({}),
    .Z({})
  );
'''

XOR_CIRCUIT = '''
  XOR {} (
    .A({}),
    .B({}),
    .Z({})
  );
'''

circuit_counter = 0
wire_counter = 0

def circuit():
    global circuit_counter
    circuit_counter += 1
    return 'C%d' % circuit_counter

def wire():
    global wire_counter
    wire_counter += 1
    return 'W%d' % wire_counter

def new_circuit(circuit_template, in1, in2, out=None):
    global payload
    if out is None:
        out = wire()
    payload += circuit_template.format(
        circuit(),
        in1,
        in2,
        out
    )
    return out

payload = ''
now = new_circuit(XOR_CIRCUIT, 'g_input[0]', 'e_input[0]')

for i in range(1, 255):
    now = new_circuit(XOR_CIRCUIT, 'g_input[%d]' % i, now)
    now = new_circuit(XOR_CIRCUIT, 'e_input[%d]' % i, now)

now = new_circuit(XOR_CIRCUIT, 'g_input[255]', now)
now = new_circuit(XOR_CIRCUIT, 'e_input[255]', now, 'o')

payload += EPILOGUE

wires = ''
for i in range(1, wire_counter+1):
    wires += '  wire W%d;\n' % i
payload = PROLOGUE + wires + payload

with open('test.v', 'w') as f:
    f.write(payload)
