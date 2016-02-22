from pwn import *

class Node:
    def __init__(self, val):
        self.left = None
        self.right = None
        self.val = val

    def add(self, val):
        if val <= self.val:
            if self.left:
                self.left.add(val)
            else:
                self.left = Node(val)
        else:
            if self.right:
                self.right.add(val)
            else:
                self.right = Node(val)

    def traverse(self):
        ret = [self.val]
        if self.right:
            ret += self.right.traverse()
        if self.left:
            ret += self.left.traverse()
        return ret

def invert(text):
    print text[:-1]
    arr = list(map(int, text[1:-2].split(', ')))

    root = Node(arr[0])

    for t in arr[1:]:
        root.add(t)

    return '['+', '.join(map(str, root.traverse()))+']'

p = remote('188.166.133.53', 11491)

for i in range(50):
    print p.recvuntil(': ')
    p.sendline(invert(p.recvline()))

print p.recvall()
