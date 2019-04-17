import binascii
import string
import sys


def xor(*t):
    from functools import reduce
    from operator import xor
    return [reduce(xor, x, 0) for x in zip(*t)]


def xor_string(t1, t2):
    t1 = map(ord, t1)
    t2 = map(ord, t2)
    return "".join(map(chr, xor(t1, t2)))

with open('output.txt', 'r') as f:
    ct = binascii.unhexlify(f.read())[:-8]

pt = '''The Song of the Count

You know that I am called the Count
Because I really love to count
I could sit and count all day
Sometimes I get carried away
I count slowly, slowly, slowly getting faster
Once I've started counting it's really hard to stop
Faster, faster. It is so exciting!
I could count forever, count until I drop
1! 2! 3! 4!
1-2-3-4, 1-2-3-4,
1-2, i love couning whatever the ammount haha!
1-2-3-4, heyyayayay heyayayay that's the sound of the count
I count the spiders on the wall...
I count the cobwebs in the hall...
I count the candles on the shelf...
When I'm alone, I count myself!
I count slowly, slowly, slowly getting faster
Once I've started counting it's really hard to stop
Faster, faster. It is so exciting!
I could count forever, count until I drop
1! 2! 3! 4!
1-2-3-4, 1-2-3-4, 1,
2 I love counting whatever the
ammount! 1-2-3-4 heyayayay heayayay 1-2-3-4
That's the song of the Count!
'''

block_size = 16

safe_len = len(pt) / block_size * block_size
pt = pt[:safe_len]

keys = set()

for i in range(safe_len / block_size):
    sliced = pt[i * block_size:(i+1) * block_size]
    candidate = xor_string(sliced, ct[i * block_size:(i+1) * block_size])
    keys.add(candidate)

for i in range(safe_len / block_size, (len(ct) + block_size - 1) / block_size):
    sliced = ct[i * block_size:(i+1) * block_size]
    for key in keys:
        decoded = xor_string(sliced, key)
        if all(map(lambda c: c in string.printable, decoded)):
            sys.stdout.write(decoded)

# p4{at_the_end_of_the_day_you_can_only_count_on_yourself}
