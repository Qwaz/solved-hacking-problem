puzzles = [
    "rbrr rgb rb  r brgrbrgb  grrgbbg grg bgrg  bbgrbg",
    "rbr  bbggrgrggb   bggbb b  b bbrbbgg gbrrbgrbbb g",
    "rrbrb rg g  bgrbgggr ggrgr gr rg brr  b  bggrbgbb",
]

PUZZLE = 0


def choose_empty(b, g, r):
    if g != 0 or b != 0:
        if b < g:
            return 'g'
        else:
            return 'b'
    else:
        return ' '


def choose_blue(b, g, r):
    if 4 >= r:
        if 4 >= g:
            if r == 2 or r == 3:
                return 'r'
            else:
                return 'b'
        else:
            return 'g'
    else:
        return ' '


def choose_red(b, g, r):
    if r != 2 and r != 3:
        return ' '
    else:
        if b == 0 or g == 0:
            return ' '
        else:
            return 'r'


def choose_green(b, g, r):
    if 4 >= r:
        if 4 >= b:
            if r == 2 or r == 3:
                return 'r'
            else:
                return 'g'
        else:
            return 'b'
    else:
        return ' '


class Game():
    def __init__(self):
        self.cur_x = 0
        self.cur_y = 0

        self.grid = [[0 for x in range(8)] for y in range(8)]
        self.cells = [[
            puzzles[PUZZLE][y * 7 + x] for x in range(7)
        ] for y in range(7)]
        self.vert_edge = [[0 for x in range(8)] for y in range(7)]
        self.hor_edge = [[0 for x in range(7)] for y in range(8)]
        self.move_buf = []

        self.grid[self.cur_y][self.cur_x] = 1

    def clone(self):
        ret = Game()

        ret.cur_x = self.cur_x
        ret.cur_y = self.cur_y

        ret.grid = [[self.grid[y][x] for x in range(8)] for y in range(8)]
        ret.cells = [[
            self.cells[y][x] for x in range(7)
        ] for y in range(7)]
        ret.vert_edge = [[self.vert_edge[y][x]
                          for x in range(8)] for y in range(7)]
        ret.hor_edge = [[self.hor_edge[y][x]
                         for x in range(7)] for y in range(8)]
        ret.move_buf = [move for move in self.move_buf]

        return ret

    def visualize(self):
        for y in range(15):
            if y % 2 == 0:
                # edges line
                buf = []
                for x in range(15):
                    if x % 2 == 0:
                        tx = x // 2
                        ty = y // 2
                        if self.cur_x == tx and self.cur_y == ty:
                            buf.append('@')
                        else:
                            buf.append('O' if self.grid[ty][tx] == 1 else '.')
                    else:
                        tx = x // 2
                        ty = y // 2
                        buf.append('=' if self.hor_edge[ty][tx] == 1 else '-')
                print("".join(buf))
            else:
                # cells line
                buf = []
                for x in range(15):
                    if x % 2 == 0:
                        tx = x // 2
                        ty = y // 2
                        buf.append('|' if self.vert_edge[ty][tx] == 1 else ':')
                    else:
                        tx = x // 2
                        ty = y // 2
                        buf.append(self.cells[ty][tx])
                print("".join(buf))

    def count_neighbor(self, x, y, cell):
        cnt = 0
        for ny in [y-1, y, y+1]:
            for nx in [x-1, x, x+1]:
                if x == nx and y == ny:
                    continue
                if 0 <= nx < 7 and 0 <= ny < 7:
                    if self.cells[ny][nx] == cell:
                        cnt += 1
        return cnt

    def step_cell(self):
        next_cells = [[None for x in range(7)] for y in range(7)]

        for y in range(7):
            for x in range(7):
                r = self.count_neighbor(x, y, 'r')
                g = self.count_neighbor(x, y, 'g')
                b = self.count_neighbor(x, y, 'b')

                if self.cells[y][x] == ' ':
                    next_cells[y][x] = choose_empty(b, g, r)
                elif self.cells[y][x] == 'r':
                    next_cells[y][x] = choose_red(b, g, r)
                elif self.cells[y][x] == 'g':
                    next_cells[y][x] = choose_green(b, g, r)
                elif self.cells[y][x] == 'b':
                    next_cells[y][x] = choose_blue(b, g, r)
                else:
                    raise "Invalid Cell"

        self.cells = next_cells

    def move_history(self):
        return "".join(self.move_buf)

    def move(self, direction):
        ret = self.clone()
        if direction == "L":
            nx = self.cur_x - 1
            ny = self.cur_y
            ex = self.cur_x - 1
            ey = self.cur_y
        elif direction == "R":
            nx = self.cur_x + 1
            ny = self.cur_y
            ex = self.cur_x
            ey = self.cur_y
        elif direction == "U":
            nx = self.cur_x
            ny = self.cur_y - 1
            ex = self.cur_x
            ey = self.cur_y - 1
        elif direction == "D":
            nx = self.cur_x
            ny = self.cur_y + 1
            ex = self.cur_x
            ey = self.cur_y
        else:
            return ("unknown direction, please use one of LRUD", None)

        if nx < 0 or nx > 7 or ny < 0 or ny > 7:
            return ("out of bound", None)

        if self.grid[ny][nx] == 1:
            return ("already visited", None)

        ret.cur_x = nx
        ret.cur_y = ny
        ret.grid[ny][nx] = 1
        if nx == self.cur_x:
            min_y = min(ny, self.cur_y)
            if not ((nx > 0 and ret.cells[min_y][nx-1] == 'r') or (nx < 7 and ret.cells[min_y][nx] == 'r')):
                return ("no red!", None)
            ret.vert_edge[ey][ex] = 1
        else:
            min_x = min(nx, self.cur_x)
            if not ((ny > 0 and ret.cells[ny-1][min_x] == 'r') or (ny < 7 and ret.cells[ny][min_x] == 'r')):
                return ("no red!", None)
            ret.hor_edge[ey][ex] = 1
        ret.move_buf.append(direction)

        ret.step_cell()

        return (None, ret)


# Manual Playing
"""
history = []
now = Game()

while True:
    print("Move history: " + now.move_history())
    now.visualize()
    cmd = input()[0].upper()
    if cmd == 'B':
        if len(history) == 0:
            print("Can't go back")
        else:
            now = history.pop()
    else:
        (err, next_state) = now.move(cmd)
        if err is not None:
            print("Err: " + err)
        else:
            history.append(now)
            now = next_state
"""


def backtracking(now):
    if now.cur_x == 7 and now.cur_y == 7:
        print(now.move_history())
        now.visualize()
        exit(0)
    for direction in "LRUD":
        (err, next_state) = now.move(direction)
        if err is None:
            backtracking(next_state)


backtracking(Game())
