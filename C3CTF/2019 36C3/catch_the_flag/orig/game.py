#!/usr/bin/env python3

import time
from flag_char import FlagChar

with open("map", "r") as f:
    lines = f.read().strip().split('\n')
    height, (width,) = len(lines), set(map(len, lines))
    mapp = list(''.join(lines))

flag = []
with open("flag.txt", "r") as f:
    tmp = f.read().strip()
    for x, i in enumerate(tmp):
        flag.append(FlagChar(i, (width // 2) - (len(tmp) // 2) + x, height // 2, width, height))

STARTING_POS = (0,0)

NOTHING = "0"
PIT = "1"
FLAG_CHAR = "2"

pos = STARTING_POS
running = True
updated_map = []

def index(x,y):
    return x + y * width

def game_loop():
    global updated_map
    slow = 2
    cnt = 0
    while True:
        if len(flag) == 0:
            print("e\x00Congrats, you caught the whole flag.")
            break
        updated_map = mapp.copy()
        # build map with current flag positions
        for i in flag:
            updated_map[index(i.x, i.y)] = FLAG_CHAR

        output = []
        # img (default room)
        output.append("i")
        # player pos
        x,y = pos
        west, north, east, south = get_neighbor_values(updated_map, x, y)

        if north == PIT or west == PIT or south == PIT or east == PIT:
            # pit: you feel cold
            output.append("breeze")
        if north == FLAG_CHAR or west == FLAG_CHAR or south == FLAG_CHAR or east == FLAG_CHAR:
            # flag: you smell a flag
            output.append("smell")
        print("\x00".join(output))

        if get_input():
            cnt += 1
            if cnt % slow == 0:
                move_flag()

def move_flag():
    global flag, updated_map
    updated_map[index(pos[0], pos[1])] = "3"
    for i in flag:
        neighbors = get_neighbor_values(updated_map, i.x, i.y)
        old_idx = index(i.x, i.y)
        i.move((neighbors[0] != NOTHING,
            neighbors[1] != NOTHING,
            neighbors[2] != NOTHING,
            neighbors[3] != NOTHING))
        updated_map[old_idx] = NOTHING
        updated_map[index(i.x, i.y)] = FLAG_CHAR

def check_catch():
    for f in flag:
        caught = f.catch(pos[0], pos[1])
        if caught:
            flag.remove(f)
            print(f"f\x00{caught}")

def get_neighbor_values(m, x, y):
    """
    return (west, north, east, south)
    """
    w = map_pos(m, x - 1, y)
    n = map_pos(m, x,     y - 1)
    e = map_pos(m, x + 1, y)
    s = map_pos(m, x,     y + 1)
    return (w, n, e, s)

def map_pos(m, x, y):
    if x < 0 or x > width - 1 or y < 0 or y > height - 1:
        return "wall"
    return m[index(x, y)]

def get_input():
    global pos
    valid = False
    while not valid:
        key = input()
        if len(key) > 1:
            print("e\x00Wrong key.")
        x,y = pos
        if key == "w":
            if y == 0:
                print("iw")
            else:
                pos = (x, y - 1)
                valid = True
        elif key == "a":
            if x == 0:
                print("iw")
            else:
                pos = (x - 1, y)
                valid = True
        elif key == "s":
            if y == height - 1:
                print("iw")
            else:
                pos = (x, y + 1)
                valid = True
        elif key == "d":
            if x == width - 1:
                print("iw")
            else:
                pos = (x + 1, y)
                valid = True
        # ignore other keys
    check_catch()

    cur_field = map_pos(updated_map, pos[0], pos[1])
    if cur_field == PIT:
        print("d")
        exit()
    return True

if __name__ == "__main__":
    game_loop()
