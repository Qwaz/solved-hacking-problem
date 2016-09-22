#!/usr/bin/env python

from pwn import *


def pay(cost, divider):
    counter = cost // divider
    p.sendline(str(counter))
    return cost - divider * counter

p = remote('misc.chal.csaw.io', 8000)

for i in range(400):
    p.recvuntil("$")

    dolor = int(p.recvuntil('.')[:-1])
    penny = int(p.recvline())

    p.recvuntil('$10,000 bills: ')
    dolor = pay(dolor, 10000)
    p.recvuntil('$5,000 bills: ')
    dolor = pay(dolor, 5000)
    p.recvuntil('$1,000 bills: ')
    dolor = pay(dolor, 1000)
    p.recvuntil('$500 bills: ')
    dolor = pay(dolor, 500)
    p.recvuntil('$100 bills: ')
    dolor = pay(dolor, 100)
    p.recvuntil('$50 bills: ')
    dolor = pay(dolor, 50)
    p.recvuntil('$20 bills: ')
    dolor = pay(dolor, 20)
    p.recvuntil('$10 bills: ')
    dolor = pay(dolor, 10)
    p.recvuntil('$5 bills: ')
    dolor = pay(dolor, 5)
    p.recvuntil('$1 bills: ')
    dolor = pay(dolor, 1)

    p.recvuntil('half-dollars (50c): ')
    penny = pay(penny, 50)
    p.recvuntil('quarters (25c): ')
    penny = pay(penny, 25)
    p.recvuntil('dimes (10c): ')
    penny = pay(penny, 10)
    p.recvuntil('nickels (5c): ')
    penny = pay(penny, 5)
    p.recvuntil('pennies (1c): ')
    penny = pay(penny, 1)

    log.success('Stage %d: %s' % (i+1, p.recvline()))

print p.recvall()
