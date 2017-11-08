from pwn import *
from z3 import *
from symbolic_mt import SymbolicMT
import subprocess

MANUAL_LEVEL = 10
mt = SymbolicMT()


def generate_prob(mt):
    for lvl in range(1, MANUAL_LEVEL+1):
        n = 4*lvl + 7
        m = min(4*lvl + 20, 120)

        ans = 0
        p = []
        x = []
        for i in range(n):
            val = 0
            t = m
            while t > 0:
                w = min(t, 32)
                mask = 0xFFFFFFFF >> (32 - w)
                val = (val << w) | (mt.generate() & mask)
                t -= w
            if mt.generate() & 1:
                val = -val
            p.append(val)
        for i in range(n):
            if mt.generate() & 1:
                ans += p[i]
                x.append(p[i])


def expect_prob(prob, m):
    for x in prob:
        x = int(x)
        minus = 1 if x < 0 else 0
        x = abs(x)

        if m > 32:
            mt.expect(32, x >> (m-32))
            mt.expect(m-32, x & ((1 << (m-32)) - 1))
        else:
            mt.expect(m, x)
        mt.expect(1, minus)

p = remote('54.92.67.18', 50216)

for lvl in range(1, 31):
    p.recvuntil('Prob %d: ' % lvl)
    ans = int(p.recvuntil(' ', drop=True))

    p.recvuntil('from ')
    prob = p.recvline().split()

    n = 4*lvl + 7
    m = min(4*lvl + 20, 120)

    if lvl <= MANUAL_LEVEL:
        expect_prob(prob, m)

        with open('input', 'w') as f:
            f.write('%d\n%d\n' % (len(prob), ans))
            f.write('%s\n' % ' '.join(map(str, prob)))

        result = subprocess.check_output('./knapsack < input', shell=True).split()
        result = list(map(int, result))

        for s in result:
            mt.expect(1, s)
    else:
        expect_prob(prob, m)
        print mt.bit_cnt, mt.gen_cnt

        mt.solver.check()
        model = mt.solver.model()

        t_ans = ans
        t_prob = []

        ans_sym = [Bool('ans_%d_%d' % (lvl, i)) for i in range(n)]
        result_sym = [Extract(0, 0, mt.generate()) for x in range(n)]
        result = []
        for i, sym in enumerate(result_sym):
            mt.solver.add(ans_sym[i] == (sym == 1))

        for i in range(n):
            solve0 = False
            solve1 = False

            if model.eval(sym) == 0:
                solve0 = True
                if mt.solver.check(ans_sym[i]) == sat:
                    solve1 = True
                mt.solver.pop()
            else:
                solve1 = True
                if mt.solver.check(Not(ans_sym[i])) == sat:
                    solve0 = True

            print lvl, i, solve0, solve1
            if solve0 and solve1:
                # the knapsack solver must be used
                result.append(-1)
                t_prob.append(prob[i])
            else:
                if solve0:
                    result.append(0)
                elif solve1:
                    result.append(1)
                else:
                    # unsat, should not be happen
                    raise Exception("Unsat!")

        with open('input', 'w') as f:
            f.write('%d\n%d\n' % (result.count(-1), t_ans))
            f.write('%s\n' % ' '.join(map(str, t_prob)))

        t_result = subprocess.check_output('./knapsack < input', shell=True).split()
        t_result = list(map(int, t_result))

        t_pos = 0
        for i in range(n):
            if result[i] == -1:
                result[i] = t_result[t_pos]
                mt.solver.add(result_sym[i] == result[i])
                t_pos += 1

    selected = map(
        lambda (num, v): num,
        filter(lambda (num, v): v == 1, zip(prob, result))
    )

    p.sendline(str(len(selected)))
    p.sendline(' '.join(selected))

    log.success('Problem %d clear' % lvl)
