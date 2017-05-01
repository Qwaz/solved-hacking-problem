from pwn import *

import subprocess

'''
[level 1]
show introduce message

[level 2]
buffer test

[level 3]
fork and check ptrace

[level 4]
shows error if traced

[level 6]
cs register becomes 0x33
enter 64-bit mode

[level 7]
print "64-bit Enabled"

[level 9]
??

[level 10]
print "Encryption Enabled"

[level 11]
root test with socketcall and setitimer
'''


def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1:
            return
        yield start
        start += len(sub)


def modify_binary(level, binary):
    if level == 3:
        # replace `int 0x80` to `xor %eax, %eax` for ptrace calls
        binary = binary + binary[0xeb:0x10f].replace('\xcd\x80', '\x31\xc0')
        for idx in find_all(binary, '\x6a\x1a\xe8'):
            binary = (
                binary[:idx] + '\x6a\x1a\xe8' +
                p32(u32(binary[idx+3:idx+7])+40) + binary[idx+7:]
            )
    if level == 7:
        context.arch = 'amd64'
    return binary


def prompt():
    global run_to
    while level >= run_to:
        command = raw_input('> ').split()

        if len(command) == 0:
            break

        if command[0] == 'help':
            print '''
help       - show help message
next       - go to next level
run (N)    - run through level N
dump       - hexdump binary
disasm (P) - disassemble this level's binary
ans        - hexdump client answer
vmmap      - shows vmmap
            '''.strip()
        elif command[0] == 'next':
            break
        elif command[0] == 'run':
            try:
                run_to = int(command[1])
            except Exception:
                run_to = 100
            break
        elif command[0] == 'dump':
            print hexdump(bin_history)
        elif command[0] == 'disasm':
            PAGE = 100

            data = disasm(bin_history)
            data = data.split('\n')
            max_page = (len(data)+99)/PAGE

            try:
                page_num = int(command[1])
            except:
                page_num = 1
            if page_num < 0 or page_num > max_page:
                page_num = 1

            print 'Page %d / %d' % (page_num, max_page)
            print '\n'.join(data[(page_num-1)*PAGE:page_num*PAGE])
        elif command[0] == 'ans':
            print hexdump(ans)
        elif command[0] == 'vmmap':
            if pid == -1:
                print 'Not Supported'
            else:
                print subprocess.check_output(('cat', '/proc/%d/maps' % pid))


client = listen(port=12345)
client.wait_for_connection()
server = remote('liberty_thisbusinessisbinaryyoureaoneorazeroaliveordead.quals.shallweplayaga.me', 11445)

pid = -1
for line in subprocess.check_output('ps u | grep ./liberty', shell=True).strip().split('\n'):
    splitted = line.split()
    if splitted[10].startswith('./liberty'):
        pid = int(splitted[1])

if pid == -1:
    log.failure('Unsupported Client')
else:
    log.success('Client pid: %d' % pid)

run_to = 0

bin_history = ''

for level in range(1, 20):
    binary_len = u32(server.recvn(4))
    binary = server.recvn(binary_len)

    log.info('[Level %d] Original Binary Size %d' % (level, binary_len))

    binary = modify_binary(level, binary)
    bin_history = binary + bin_history[len(binary):]

    client.send(p32(len(binary)))
    client.send(binary)

    try:
        ans_len = u32(client.recvn(4))
        ans = client.recvn(ans_len)
        server.send(p32(ans_len))
        server.send(ans)

        log.success('Answer Size - %d' % ans_len)
        prompt()
    except Exception:
        log.failure('Client is dead')
        prompt()
        break
