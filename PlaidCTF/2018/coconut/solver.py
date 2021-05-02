from pwn import *
import subprocess

p = remote('coconut.chal.pwning.xxx', 6817)

stage = 1
try:
    while True:
        log.info('Stage %d' % stage)
        stage += 1

        p.recvuntil('Function to optimize:\n')
        program = p.recvuntil('<<<EOF>>>\n')

        p.recvuntil('Example input:\n')
        p.recvuntil('can only be >=')
        line_from = int(p.recvuntil(' ', drop=True))
        p.recvuntil('and <=')
        line_to = int(p.recvuntil(':\n', drop=True))

        with open('input.txt', 'w') as f:
            f.write(program)
            f.write('{} {}\n'.format(line_from, line_to))

        with open('input%d.txt' % stage, 'w') as f:
            f.write('{} {}\n'.format(line_from, line_to))
            f.write(program)

        process = subprocess.Popen(['target/release/coconut.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = process.communicate()

        p.send(out)
except:
    pass

p.interactive()
