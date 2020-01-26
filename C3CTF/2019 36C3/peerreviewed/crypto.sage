#!/usr/bin/env sage

# A. G. D. Uchoa, M. E. Pellenz, A. O. Santin, and C. A. Maziero.
# "A three-pass protocol for cryptography based on padding for wireless networks."
# In: 2007 4th IEEE Consumer Communications and Networking Conference.
# IEEE, Jan. 2007, pp. 287--291. DOI: 10.1109/CCNC.2007.63.
#
# For those without IEEE subscriptions, this paper is also available through
# ResearchGate and Google Scholar.

from Crypto.Util.number import bytes_to_long, long_to_bytes
from itertools import izip_longest

# Settings from Section IV of the paper
R = RealField(prec=200)
block_size = 192

# Key generation
def rotate_2d(field, theta):
    # Rotation matrix (clockwise, as in Section III)
    return matrix(field, [[cos(theta), sin(theta)], [-sin(theta), cos(theta)]])

def generate_key():
    # Pick a random angle on the unit circle
    circle = 2 * R.pi()
    theta = R(random()) * circle
    # Follow Section III to generate the rest of the key:
    # Build the rotation matrix O and its inverse
    O = rotate_2d(R, theta)
    Oc = rotate_2d(R, circle - theta)
    # Generate the nonce matrix (with 1 <= a, b <= 2**64)
    a = randint(1, 2**64)
    b = randint(1, 2**64)
    A = matrix(R, [[a, b], [-b, a]])
    Ac = A.transpose() / A.det()
    return O, Oc, A, Ac

# Message handling
def split_message(message, block_size):
    # Convert to bits
    message = Integer(bytes_to_long(message)).bits()
    # Add padding
    message += [1]
    padding_required = block_size - len(message) % block_size
    if padding_required != block_size:
        message += [0] * padding_required
    # Split into blocks
    for block_start in range(0, len(message), block_size):
        yield Integer(message[block_start:block_start+block_size][::-1], base=2)

def merge_message(blocks):
    # Merge blocks
    blocks = [Integer(round(block)).bits()[::-1] for block in blocks]
    blocks = [[0] * (block_size - len(block)) + block for block in blocks]
    bits = flatten(blocks)
    # Remove padding
    bits = bits[:-bits[::-1].index(1)-1]
    # Convert back
    return long_to_bytes(Integer(bits, base=2))

def group(iterable, n, fill=None):
    iters = [iter(iterable)] * n
    return izip_longest(*iters, fillvalue=fill)

# Self-test for encryption and decryption
if __name__ == '__main__':
    from message import m
    blocks = split_message(m, block_size)
    results = []
    for b1, b2 in group(blocks, 2, Integer(0)):
        b = vector(R, [b1, b2])
        # Generate keys for both sides
        O1, Oc1, A1, Ac1 = generate_key()
        O2, Oc2, A2, Ac2 = generate_key()
        # Simulate transmission
        yA = b * O1 * A1
        print 'A -> B: yA =', yA
        yB = yA * O2 * A2
        print 'B -> A: yB =', yB
        yC = yB * Oc1 * Ac1
        print 'A -> B: yC =', yC
        x = yC * Oc2 * Ac2
        # Collect results
        results.extend(x)
    assert m == merge_message(results), 'Test failed'
