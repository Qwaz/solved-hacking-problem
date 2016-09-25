#!/usr/bin/python

from secret import p_prime, q_prime, r, key, flag
flag = flag * r

def encrypt(msg, p, q, r, key):
    enc = ''
    for i in range(len(msg)):
        enc += chr( i ** p % p ^ ord(msg[i]) ** q % (q ** 2 - 6 * q + 6) ^ ord(key[r * i % len(key)]) )
    return enc

f = open('enc', 'w')
f.write(encrypt(flag, p_prime, q_prime, r, key))
f.close() 
