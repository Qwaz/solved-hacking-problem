#!/usr/bin/env python

from pwn import *

# p = remote('chal.cykor.kr', 20000)
p = process('f65c09977d6a4adf8949dcb05544a998/bh')

ITEM = 0
NUMBER = 1
STRING = 2
STORAGE = 3


def recv():
    length = u32(p.recvn(4))
    return p.recvn(length)


def send(msg):
    p.send(p32(len(msg)))
    p.send(msg)


def op_add(ref1, ref2):
    send('\x00' + chr(ref1) + chr(ref2))
    return recv()


def op_define_number(integer):
    if integer < 0:
        integer += 2147483648 * 2
    send('\x01' + chr(NUMBER) + p32(integer))
    return recv()


def op_define_string(msg):
    send('\x01' + chr(STRING) + p32(len(msg)) + msg)
    return recv()


def op_define_storage():
    # item_count / key(string), value(item) / ...
    send('\x01' + chr(STORAGE) + p32(0))
    return recv()


def op_set(ref, key_ref, val_ref):
    send('\x03' + chr(ref) + chr(key_ref) + chr(val_ref))
    return recv()


def op_eval(string_ref):
    send('\x04' + chr(string_ref))
    return recv()


def op_if(ref, jump):
    send('\x05' + chr(ref) + p32(jump))
    return recv()


def op_return(ref):
    send('\x06' + chr(ref))
    return recv()


def op_convert(ref, type, base=0):
    if type != NUMBER:
        send('\x07' + chr(ref) + chr(type))
    else:
        send('\x07' + chr(ref) + chr(type) + chr(base-1))
    return recv()


log.info(recv())
log.info(recv())
log.info(recv())
