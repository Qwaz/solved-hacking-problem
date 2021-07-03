import struct
data = open(r'baby-a-fallen-lap-ray/p', 'rb').read()

pc = 0
def byte():
	global pc
	res = data[pc]
	pc += 1
	return res

def word():
	a = byte()
	b = byte()
	return a + b * 256

def bit(x):
	x = bin(x)[2:]
	assert x.count('1') == 1, x
	return len(x) - 1

def reg(x):
	return ['r0', 'r1', 'r2', 'r3', 'sp', 'pc'][bit(x)]

disasm = []
label = {
	0x13c: 'func_add',
	0x17c: 'do_add',
	0x14c: 'func_list',
	0x3c8: 'do_list',
	0x15c: 'func_view',
	0x53c: 'do_view',
	0x7ac: 'write_str',
	0x7fc: 'write_int',
	0x870: 'read_line',
	0x91c: 'multiply',
	0xaaa: '$log_count @ aaa',
  0xc2f: '$max_log @ c2f',
}
xrefs = {}

def _(fmt, *args):
	disasm.append((addr, fmt, args))

def mark(addr):
	if all(32 <= x <= 126 for x in data[addr:addr+3]):
		return hex(addr) + " ; \"%s\"" % repr(data[addr:].split(b'\x00')[0].decode())[1:-1]
	if addr > len(data) - 4 or (data[pc] != 0x20 and struct.unpack("<H", data[pc + 6:pc + 8])[0] not in label):
		if addr >= 0x980:
			unpacked = struct.unpack("<Q", data[addr:addr+8])[0]
			if 0 < unpacked < 0x100:
				return hex(addr) + " ; =" + hex(unpacked)
		return hex(addr)

	xrefs[addr] = xrefs.get(addr, []) + [pc - 4]
	if addr not in label:
		label[addr] = l = 'loc_%x' % addr
	else:
		l = label[addr]
	return l

def cond(a):
	if a == 4:
		return 'eq'
	else:
		return 'cc:%d' % a

while pc < len(data) - 4:
	addr = pc
	op = byte()
	a, b, c = byte(), byte(), byte()
	if op in (2, 4, 8, 16, 32, 64, 128):
		assert c == 0, (op, a, b, c)
	if op == 1:
		_('ldi', reg(a), mark(b + c * 0x100))
	elif op == 2:
		assert a or b
		if a:
			_('pop', reg(a))
		else:
			_('push', reg(b))
		# _('mov', bit(a), bit(b))
	elif op == 0x20:
		if a == 0:
			_('branch', reg(b))
		else:
			_('b' + cond(a), reg(b))
	elif op == 0x10:
		a = reg(a)
		b = reg(b)
		_('load', a, b)
	elif op == 0x80:
		_('syscall', bit(a), reg(b))
	elif op == 0x04:
		_('add', reg(a), reg(b))
	elif op == 0x08:
		_('str', reg(a), reg(b))
	elif op == 0x40:
		_('cmp', reg(a), reg(b))
	else:
		# print("Unknown opcode:", bytes([op, a, b, c]))
		break

for addr, fmt, args in disasm:
	if addr in label:
		print()
		print(label[addr] + ":")
		for x in xrefs.get(addr, []):
			print('; XREFS FROM', mark(x))
	print(fmt.ljust(20), ', '.join(map(lambda x: x if type(x) is str else str(x), args)))
