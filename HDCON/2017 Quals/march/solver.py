'''
000004FA 004010FA -> 0E to 0D
00000803 00401403 -> 75 to 74

get_onion: 0x4010f0

init_buf: 0x401050
strcpy_to_food: 0x401190

vtable: 0x40E240
'''

import hashlib

addr_list = [0x40E240, 0x40107F]
addr_sum = sum(addr_list)

m = hashlib.md5()
m.update(str(addr_sum).encode('ascii'))
print(m.hexdigest())
