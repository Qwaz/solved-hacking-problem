import os

for i in range(10000, 10100):
    pid = os.fork()

    if pid == 0:
        # child
        os.system('nc -l {}'.format(i))
        break
