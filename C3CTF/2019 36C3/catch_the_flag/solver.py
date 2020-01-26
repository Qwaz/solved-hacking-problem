#!/usr/bin/env python3
# hxp{and_n0w_try_t0_c4tch_m3_w1th0ut_dy1ng}

import socket
import sys
import random
import time
from queue import Queue


class FlagChar:
    def __init__(self, idx, x, y, width, height):
        self.idx = idx
        self.x = x
        self.y = y
        self.width, self.height = width, height

    def move(self, fields):
        """
        fields: (0,1,2,3)
             1
        0 current 2
             3
        True = something is there
        """
        # 10 tries, else do not move
        for _ in range(10):
            s = random.randint(0, 3)
            if s == 1 and (self.y <= 0 or fields[1]):
                continue
            if s == 0 and (self.x <= 0 or fields[0]):
                continue
            if s == 2 and (self.x >= (self.width - 1) or fields[2]):
                continue
            if s == 3 and (self.y >= (self.height - 1) or fields[3]):
                continue
            if s == 0:
                self.x -= 1
            if s == 1:
                self.y -= 1
            if s == 2:
                self.x += 1
            if s == 3:
                self.y += 1
            # we moved, break loop
            break

    def catch(self, x, y):
        if self.x == x and self.y == y:
            return self.idx
        else:
            return None


HOST = "78.47.17.200"
PORT = 7888

WIDTH = 50
HEIGHT = 50

FLAG_LEN = 42

flag_char = ['?' for _ in range(FLAG_LEN)]
remain = FLAG_LEN


with open("map", "r") as f:
    atlas = f.read().split('\n')


def receive_until_prompt(sock, prompt=b"\n"):
    received = b""
    buf_size = len(prompt)
    while True:
        new = sock.recv(buf_size)
        received += new
        for i in range(1, len(prompt) + 1):
            if received.endswith(prompt[-i:]):
                if i == len(prompt):
                    return received
            else:
                buf_size = len(prompt) - i + 1
        if not new:
            raise Exception(
                "Connection closed before {} was found".format(prompt))


def recv(sock):
    data = receive_until_prompt(sock)
    data = data.strip()
    data = data.split(b"\x00")
    return tuple(map(lambda x: x.decode(), data))


def expect_room(sock):
    while True:
        data = recv(sock)
        if data[0] == 'd':
            return False
        elif data[0] == 'i':
            print('Data: ' + ' '.join(data[1:]))
            return True
        elif data[0] == 'e':
            print('Message: ' + data[1])
        elif data[0] == 'f':
            cy, cx = current_pos
            for f in flag:
                index = f.catch(cx, cy)
                if index is not None:
                    flag.remove(f)
                    flag_char[index] = data[1]
                    print("Caught flag %d: %c" % (index, data[1]))


def move(s, direction):
    s.sendall("{}\n".format(direction).encode())


def latest_map():
    updated = [[atlas[y][x] for x in range(WIDTH)] for y in range(HEIGHT)]
    cy, cx = current_pos
    updated[cy][cx] = 'C'

    for f in flag:
        updated[f.y][f.x] = 'F'

    return updated


def print_map():
    updated = latest_map()
    for y in range(HEIGHT):
        print(''.join(updated[y]))
    print('Flag: ' + ''.join(flag_char))


def move_flag():
    updated = latest_map()

    def pos(x, y):
        if x < 0 or x > WIDTH - 1 or y < 0 or y > HEIGHT - 1:
            return "#"
        return updated[y][x]

    for i in flag:
        neighbors = (
            pos(i.x-1, i.y) != SAFE,
            pos(i.x, i.y-1) != SAFE,
            pos(i.x+1, i.y) != SAFE,
            pos(i.x, i.y+1) != SAFE,
        )
        old_y, old_x = i.y, i.x
        i.move(neighbors)
        updated[old_y][old_x] = SAFE
        updated[i.y][i.x] = 'F'


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

flag = []

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # adjust offset correctly
        random.seed(int(time.time()))
        for i in range(FLAG_LEN):
            flag.append(FlagChar(i, (WIDTH // 2) - (FLAG_LEN // 2) +
                                 i, HEIGHT // 2, WIDTH, HEIGHT))

        assert expect_room(s)  # first room data

        current_pos = (0, 0)
        cnt = 0

        while True:
            print_map()
            direction = input().strip()
            if len(direction) != 1 or direction not in 'wasd':
                print("Use wasd")
                continue

            cy, cx = current_pos
            index = 'wasd'.index(direction)
            dy = DIR[index][1]
            dx = DIR[index][2]

            # move
            ny = cy + dy
            nx = cx + dx

            if not (0 <= ny < HEIGHT and 0 <= nx < WIDTH):
                print("Don't hit the wall")
                continue

            if atlas[ny][nx] == 'X':
                print("Don't go into the pit")
                continue

            # check_catch
            move(s, direction)
            current_pos = (ny, nx)
            assert expect_room(s)

            cnt += 1
            if cnt % 2 == 0:
                # move flag
                move_flag()
