
import sys
import random
import time

class FlagChar:

    def __init__(self, char, x, y, width, height):
        self.char = char
        self.x = x
        self.y = y
        self.width, self.height = width, height
        random.seed(int(time.time()))

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
            s = random.randint(0,3)
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
            return self.char
        else:
            return None
