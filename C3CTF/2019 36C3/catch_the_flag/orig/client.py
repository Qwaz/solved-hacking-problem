#!/usr/bin/env python3

import socket
import curses
import time
import sys

window = None
stdscr = None

if len(sys.argv) != 3:
    print("Usage: python3 client.py <HOST> <PORT>")
    exit()

HOST = sys.argv[1]
PORT = int(sys.argv[2])

rows = 0
cols = 0

display_char = None
last = []

with open("images/room.txt", "r") as f:
    room = f.read().split("\n")
with open("images/breeze.txt", "r") as f:
    breeze = f.read().split("\n")
with open("images/smell.txt", "r") as f:
    smell = f.read().split("\n")
with open("images/lights.txt", "r") as f:
    lights = f.read().split("\n")
with open("images/lights-2.txt", "r") as f:
    lights_2 = f.read().split("\n")
with open("images/flag_char.txt", "r") as f:
    flag_char = f.read().split("\n")


def print_border():
    for i in range(22):
        window.addstr(2 + i, 2, " ", curses.color_pair(5))
        window.addstr(2 + i, 68, " ", curses.color_pair(5))
    for i in range(67):
        window.addstr(1, 2 + i, " ", curses.color_pair(5))
        window.addstr(23, 2 + i, " ", curses.color_pair(5))


def print_img(additional=curses.A_NORMAL):
    global window
    for counter, line in enumerate(room):
        window.addstr(2 + counter, 2, line, additional)
    print_additionals(lights, curses.color_pair(2) | curses.A_BLINK)
    print_additionals(lights_2, curses.color_pair(2))
    print_border()
    window.refresh()


def print_additionals(elem, specifics=curses.A_NORMAL):
    for counter, line in enumerate(elem):
        for ccounter, char in enumerate(line):
            if char != " ":
                window.addstr(2 + counter, 2 + ccounter, char, specifics)


def change_size():
    global rows, cols
    rows, cols = stdscr.getmaxyx()
    if rows < 22 or cols < 70:
        text_center(
            "The window is too small, make sure, your console is at least 21 rows and 69 cols large.")


def end():
    window.clear()
    text_center("bye")
    time.sleep(2)
    curses.endwin()
    exit()


def text_center(text, y=11, specifics=curses.A_NORMAL):
    window.clear()
    text_len = len(text)
    if text_len < 68:
        left = (70 - text_len) // 2
    else:
        left = 0
    window.addstr(y, left, text, specifics)
    print_border()
    window.refresh()


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
    return data


def game_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = recv(s)
        parse_data(data)
        change_size()
        while True:
            while True:
                key = window.getkey()
                if key == "KEY_RESIZE":
                    change_size()
                if key == "w" or key == "a" or key == "s" or key == "d":
                    break
            window.refresh()
            s.sendall("{}\n".format(key).encode())
            again = True
            while again:
                data = recv(s)
                again = parse_data(data)


def parse_data(data):
    global display_char, last
    if data[0] == b"c":
        text_center(data[1])
    elif data[0] == b"e":
        text_center(data[1], 11, curses.color_pair(1))
    elif data[0] == b"i":
        last = data
        print_img()
        print_additionals(flag_char, curses.color_pair(2))
        for i in range(1, len(data)):
            obj, add = additionals[data[i].decode()]
            print_additionals(obj, add)
        if display_char:
            window.addstr(11, 47, display_char)
            display_char = None
    elif data[0] == b"iw":
        print_img(curses.color_pair(1))
        time.sleep(.5)
        data = last
        print_img()
        print_additionals(flag_char, curses.color_pair(2))
        for i in range(1, len(data)):
            obj, add = additionals[data[i].decode()]
            print_additionals(obj, add)
        if display_char:
            window.addstr(11, 47, display_char)
            display_char = None
    elif data[0] == b"d":
        # dead
        text_center("You dead", 11, curses.A_BLINK | curses.color_pair(1))
        time.sleep(2)
        text_center("You dead", 11, curses.A_NORMAL | curses.color_pair(1))
        window.refresh()
        window.getkey()
        end()
    elif data[0] == b"f":
        display_char = data[1]
        return True
    return False


def main(w):
    global window, additionals, stdscr
    window = w
    window.clear()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_WHITE)
    stdscr = curses.initscr()
    curses.curs_set(0)
    additionals = {
        "breeze": (breeze, curses.color_pair(4)),
        "smell": (smell, curses.color_pair(3)),
    }
    game_loop()
    end()


if __name__ == "__main__":
    curses.wrapper(main)
