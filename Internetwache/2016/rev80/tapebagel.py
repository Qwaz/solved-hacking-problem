import sys

command = input().split()

arr = [0, 0, 0]
p = 0

for c in command:
    if c == '%#': p = (p+1)%3
    elif c == '%%': p = 0
    elif c == '#%': arr = [1, 1, 1]
    elif c == '##': arr = [0, 0, 0]
    elif c == '%++': arr[p] += 1
    elif c.startswith('@@'): sys.stdout.write(arr[len(c)-3])
    elif c.startswith('@'): sys.stdout.write(chr(ord('A')-1 + arr[len(c)-2]))
    else:
        f = s = -1
        op = ''
        for k in c:
            if k == '*':
                if op == '':
                    f += 1
                else:
                    s += 1
            else:
                op = k
        if op == '&': arr[p] = arr[f]*arr[s]
        elif op == '+': arr[p] = arr[f]+arr[s]
        elif op == '$': arr[p] = arr[f]/arr[s]
        elif op == '-': arr[p] = arr[f]-arr[s]
