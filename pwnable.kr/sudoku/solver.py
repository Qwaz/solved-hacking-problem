#!/usr/bin/env python

from pwn import *
import copy


class Board:
    def __init__(self):
        self.board = []

    def __str__(self):
        s = ''
        for y in range(9):
            s += ', '.join(map(str, self.board[y])) + '\n'
        return s

    def copy(self):
        ret = Board()
        for i in range(9):
            ret.board.append(copy.copy(self.board[i]))
        return ret

    def solve(self, validator, cells):
        cand = []

        for y in range(9):
            for x in range(9):
                if self.board[y][x] == 0:
                    possibility = [1 for i in range(10)]
                    for cy in range(9):
                        possibility[self.board[cy][x]] = 0
                    for cx in range(9):
                        possibility[self.board[y][cx]] = 0
                    dx = x // 3 * 3
                    dy = y // 3 * 3
                    for cy in range(dy, dy+3):
                        for cx in range(dx, dx+3):
                            possibility[self.board[cy][cx]] = 0
                    possibility = filter(
                        lambda x: x > 0,
                        [i if possibility[i] else 0 for i in range(10)]
                    )
                    cand.append((len(possibility), (y, x), possibility))

        cand.sort()

        if len(cand) == 0:
            sum = 0
            for cell in cells:
                sum += self.board[cell[0]][cell[1]]
            return self if validator(sum) else None
        else:
            if cand[0][0] == 0:
                return None
            else:
                for num in cand[0][2]:
                    cy = cand[0][1][0]
                    cx = cand[0][1][1]
                    newBoard = self.copy()
                    newBoard.board[cy][cx] = num
                    ans = newBoard.solve(validator, cells)
                    if ans:
                        return ans
                return None

p = remote('localhost', 9016)

p.recvuntil('press enter to see example.\n\t\n')
p.sendline('')
p.recvuntil('press enter to start game\n')
p.sendline('')
for i in range(100):
    p.recvuntil('Stage ')
    stage = int(p.recvline())
    log.info('stage %d' % stage)
    p.recvline()

    level = Board()
    for line in range(9):
        line_txt = p.recvline()[1:-2]
        level.board.append(map(int, line_txt.split(', ')))

    print level

    p.recvuntil('sum of the following numbers (at row,col) should be ')
    condition = p.recvline().split()
    cells = []

    lines = p.recvuntil('solution? : ')
    for line in lines.split('\n')[:-1]:
        cells.append((int(line[-4])-1, int(line[-2])-1))

    def validate(x):
        if condition[0] == 'bigger':
            return x > int(condition[2])
        elif condition[0] == 'smaller':
            return x < int(condition[2])

    ans = level.solve(validate, cells)
    p.sendline(str(ans.board).replace(' ', ''))

p.interactive()
