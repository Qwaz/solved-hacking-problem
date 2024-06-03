import sys
from random import SystemRandom
from Crypto.Util.number import getStrongPrime

def show(data):
    data = "".join(map(str, data))
    sys.stdout.write(data)
    sys.stdout.flush()

def input():
    return sys.stdin.readline().strip()

def main():
    show('Welcome to the FactorGame\n')
    show("The Game is simple factor N given N and bits of p, q\n")
    show("you have 5 lives for each game\n")
    show("win 8 out of 10 games to get the flag\n")
    show("good luck\n\n")
    
    known = 264
    success = 0

    for i in range(10):
        show(f"game{i + 1} start!\n")
        life = 5
        while life > 0:
            p = getStrongPrime(512)
            q = getStrongPrime(512)
            N = p * q

            cryptogen = SystemRandom()
            counter = 0

            while counter < 132 * 2 or counter > 137 * 2:
                counter = 0
                p_mask = 0
                q_mask = 0
                for _ in range(known):
                    if cryptogen.random() < 0.5:
                        p_mask |= 1
                        counter += 1
                    if cryptogen.random() < 0.5:
                        q_mask |= 1
                        counter += 1
                    p_mask <<= 1
                    q_mask <<= 1

            p_redacted = p & p_mask
            q_redacted = q & q_mask

            show(f'p : {hex(p_redacted)}\n')
            show(f'p_mask : {hex(p_mask)}\n')
            show(f'q : {hex(q_redacted)}\n')
            show(f'q_mask : {hex(q_mask)}\n')
            show(f'N : {hex(N)}\n')

            show('input p in hex format : ')
            inp = int(input(), 16)
            show('input q in hex format : ')
            inq = int(input(), 16)

            if inp == p and inq == q:
                success += 1
                show('success!\n')
                break
            else:
                show('wrong p, q\n')
                life -= 1
                show(f'{life} lives left\n')

    if success >= 8:
        show('master of factoring!!\n')
        flag = open('/flag', 'r').read()
        show(f'here is your flag : {flag}\n')
    else:
        show('too bad\n')
        show('mabye next time\n')
    exit()

if __name__ == "__main__":
    main()