#!/usr/bin/env python3

import sys
import random

width, height = map(int, sys.argv[1:3])

NOTHING = "0"
PIT = "1"

with open("flag.txt", "r") as f:
    flag = f.read()

world = []

for i in range(width * height):
    if random.random() < 0.1:
        world.append(PIT)
    else:
        world.append(NOTHING)

for i in range(len(flag)):
    world[(height // 2) * width + (width // 2) - len(flag) // 2 + i] = NOTHING

# starting position
world[0] = NOTHING

with open("map", "w+") as f:
    for i in range(width * height):
        if i == 0:
            continue
        if (i % width - 1) == 0 and i > 1:
            f.write("\n")
        f.write(world[i])
    f.write("0")
