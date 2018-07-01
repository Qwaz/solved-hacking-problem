# encoding: utf-8
# SCTF{S0_L0ng_4nd_7h4nks_f0r_A11_7h3_L4mbd4}
import binascii

from pwn import *

context.log_level = 'warning'

test_flag = '01001'

acc = 'zero'
for bit in test_flag:
    acc = '(λx.λy.λz.z x y) %s (%s)' % (('zero', 'one')[int(bit)], acc)

lib = (
    ('zero', 'λf.λx.x'),
    ('one', 'λf.λx.f x'),

    ('true', 'λa.λb.a'),
    ('false', 'λa.λb.b'),

    ('timeout', '(λx.x x x) (λx.x x x)'),

    # ('flag', acc),
)

head = ''
tail = ''
for (k, v) in lib:
    head = head + '(λ{}.'.format(k)
    tail = ' ({}))'.format(v) + tail

bit_all = 43 * 8
bit_str = ''
for bit in range(bit_all):
    payload = 'λflag.(flag %s) timeout zero' % ('false ' * bit + 'true')

    p = remote('beautyoflambda.eatpwnnosleep.com', 42)
    p.sendline('({}({})){}'.format(head, payload, tail))

    result = '1' if 'Timeout' in p.recvline() else '0'
    bit_str += result

    print '%03d / %03d - %s' % (bit, bit_all, result)

    p.close()

print binascii.unhexlify('%043x' % int(bit_str, 2))
