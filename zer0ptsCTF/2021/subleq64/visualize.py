import sys

with open("subleq64.sq") as f:
    mem = list(map(int, f.read().split()))
    accessed = [False for _ in range(len(mem))]

outgoing = [set() for _ in range(len(mem))]
incoming = [set() for _ in range(len(mem))]


def reserve(num):
    global mem, accessed, outgoing, incoming

    if len(mem) <= num:
        to_append = num - len(mem) + 1
        mem += [int(0) for _ in range(to_append)]
        accessed += [False for _ in range(to_append)]
        outgoing += [set() for _ in range(to_append)]
        incoming += [set() for _ in range(to_append)]


def add_edge(s, t):
    outgoing[s].add(t)
    incoming[t].add(s)


print(f"Initial mem length: {len(mem)}")


remaining_run = 20000000

pc = 0

while remaining_run > 0:
    accessed[pc] = True

    a = mem[pc]
    b = mem[pc + 1]
    c = mem[pc + 2]

    if a < 0 or (b < 0 and b != -1):
        print("segmentation fault")
        exit(1)

    if b == -1:
        reserve(a)

        sys.stdout.write(chr(mem[a] & 0xff))

        assert c == pc + 3
        add_edge(pc, pc + 3)
        pc += 3
    else:
        reserve(a)
        reserve(b)

        mem[b] -= mem[a]

        if mem[b] > 0:
            add_edge(pc, pc + 3)
            pc += 3
        else:
            add_edge(pc, c)
            pc = c

    remaining_run -= 1

# Path compression
path_id = [None for _ in range(len(mem))]
path_range = []

for node in range(3):
    if accessed[node]:
        new_id = len(path_range)
        path_range.append([node, node])
        path_id[node] = new_id

for node in range(3, len(mem)):
    if accessed[node]:
        if (len(outgoing[node - 3]) == 1
            and len(incoming[node]) == 1
            and node in outgoing[node - 3]
            and (node - 3) in incoming[node]
        ):
            new_id = path_id[node - 3]
            path_range[new_id][1] = node
        else:
            new_id = len(path_range)
            path_range.append([node, node])
        path_id[node] = new_id

graph = "digraph subleq {\n"

for path in range(len(path_range)):
    graph += f'    n{path} [label="{path_range[path][0]}..{path_range[path][1]}"];\n'

for node in range(len(mem)):
    for next_node in outgoing[node]:
        path = path_id[node]
        next_path = path_id[next_node]

        if path != next_path and path is not None and next_path is not None:
            graph += f'    n{path} -> n{next_path};\n'

graph += "}\n"

with open("graph.dot", "w") as f:
    f.write(graph)
