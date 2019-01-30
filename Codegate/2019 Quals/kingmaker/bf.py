data = '''1 // 2 0 0 1 0
2 // 2 0 1 0 0
3 // 2 0 2 1 0

1 // 0 0 1 0 2
2 // 0 -1 0 0 -1
3 // 0 2 0 0 0

1 // -1 0 -1 1 0
2 1 1 // 1 1 0 0 0
2 1 2 // 1 1 0 0 0
3 1 // 1 2 0 0 0

1 1 // 1 1 0 2 0
1 2 // 1 1 1 2 0
2 1 // 1 1 1 1 2
2 2 // 1 2 2 1 2

1 // 0 0 1 1 0
2 // 0 -1 2 0 0
3 // 0 -1 1 1 0

1 2 // 1 -1 -1 2 2
2 1 // 0 0 0 0 0
2 3 // 1 0 0 0 1

?? // 0 1 1 2 0

1 1 2 // 0 1 1 1 0
1 2 // 0 1 0 0 0
2 // 0 1 0 0 0

2 1 1 // -1 0 0 1 1
2 1 2 // 0 0 1 2 1
3 2 // 0 0 0 2 2'''

def parse(ll):
    def parse_line(l):
        li = l.index(' // ')
        return (l[:li], map(int, (l[li + 4:]).split(' ')))
    return map(parse_line, ll.split('\n'))

sp = map(parse, data.split('\n\n'))
print sp


def bf(level, history, stat):
    if level == len(sp):
        if stat[0] == 5 and stat[1] == 5 and stat[2] == 5 and stat[3] == 5 and stat[4] == 5:
            print history
            exit(0)
    else:
        for (data, d) in sp[level]:
            new_stat = [stat[i] + d[i] for i in range(5)]
            bf(level+1, history + [data], new_stat)

bf(0, [], [0 for i in range(5)])
