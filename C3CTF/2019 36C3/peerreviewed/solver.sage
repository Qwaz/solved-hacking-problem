from Crypto.Util.number import bytes_to_long, long_to_bytes
from itertools import izip_longest

# Settings from Section IV of the paper
R = RealField(prec=200)
block_size = 192

def rotate_2d(field, theta):
    return matrix(field, [[cos(theta), sin(theta)], [-sin(theta), cos(theta)]])

def merge_message(blocks):
    # Merge blocks
    blocks = [Integer(round(block)).bits()[::-1] for block in blocks]
    blocks = [[0] * (block_size - len(block)) + block for block in blocks]
    bits = flatten(blocks)
    # Remove padding
    bits = bits[:-bits[::-1].index(1)-1]
    # Convert back
    return long_to_bytes(Integer(bits, base=2))

with open("intercepted.txt", "r") as f:
    def parse_next():
        return map(R, f.readline()[14:-2].split(', '))

    results = []
    for i in range(3):
        ax, ay = parse_next()
        bx, by = parse_next()
        cx, cy = parse_next()

        angleA = arctan2(ay, ax)
        szA = sqrt(ax * ax + ay * ay)
        angleB = arctan2(by, bx)
        szB = sqrt(bx * bx + by * by)

        sz_change = szB / szA
        angle_change = angleB - angleA

        x, y = rotate_2d(R, angle_change) * vector(R, [cx, cy]) / sz_change

        results.extend([x, y])

    print(merge_message(results))
