from pwn import *

from Queue import Queue

WIDTH = 50
HEIGHT = 50


def recv(p):
    return p.recvline().strip().split("\x00")


def expect_room(p):
    while True:
        data = recv(p)
        if data[0] == 'd':
            return False
        elif data[0] == 'i':
            return True


"""
0 --> W
|  w
| a d
v  s
H
"""

DIR = (('w', -1, 0), ('a', 0, -1), ('s', +1, 0), ('d', 0, +1))

UNKNOWN = 'O'
PENDING = '?'
SAFE = '.'
DANGER = 'X'

guess = [[UNKNOWN for _ in range(WIDTH)] for _ in range(HEIGHT)]

guess[0][0] = SAFE
guess[0][1] = PENDING
guess[1][0] = PENDING

targets = Queue()
targets.put((0, 1))
current_target = (1, 0)


def print_map():
    print ''.join(['=' for _ in range(WIDTH)])
    for y in range(HEIGHT):
        print ''.join(guess[y])
    print ''.join(['=' for _ in range(WIDTH)])


def safe_path():
    fill = [[None for _ in range(WIDTH)] for _ in range(HEIGHT)]
    sy, sx = current_pos
    fill[sy][sx] = (sy, sx)
    ty, tx = current_target

    q = Queue()
    q.put((sy, sx))
    while fill[ty][tx] is None:
        cy, cx = q.get()
        for c, dy, dx in DIR:
            ny = cy + dy
            nx = cx + dx
            if 0 <= ny < HEIGHT and 0 <= nx < WIDTH and fill[ny][nx] is None:
                if (ny == ty and nx == tx) or guess[ny][nx] == SAFE:
                    fill[ny][nx] = (c, cy, cx)
                    q.put((ny, nx))

    s = ''
    while True:
        c, ny, nx = fill[ty][tx]
        s += c
        if ny == sy and nx == sx:
            return s[::-1]
        ty, tx = ny, nx


def explore(p):
    global current_pos, current_target

    path = safe_path()
    for i in range(len(path) - 1):
        p.sendline(path[i])
        assert expect_room(p)
    p.sendline(path[len(path) - 1])

    ty, tx = current_target
    if not expect_room(p):
        # died
        guess[ty][tx] = DANGER
        if targets.empty():
            # finished
            current_target = None
        else:
            current_target = targets.get()
        return False
    else:
        # safe
        guess[ty][tx] = SAFE

        if targets.empty():
            # finished
            current_target = None
            return False

        current_pos = (ty, tx)
        current_target = targets.get()

        for _, dy, dx in DIR:
            ny = ty + dy
            nx = tx + dx
            if 0 <= ny < HEIGHT and 0 <= nx < WIDTH and guess[ny][nx] is UNKNOWN:
                guess[ny][nx] = PENDING
                targets.put((ny, nx))

        return True


while True:
    p = remote("78.47.17.200", 7888)
    recv(p)  # remove first room

    current_pos = (0, 0)

    while explore(p):
        print_map()

    p.close()

    if current_target is None:
        # finished
        print_map()
        break
