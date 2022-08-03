from concurrent.futures import ThreadPoolExecutor
from pwn import *

context.log_level = 'warn'

verified = []
def update_verified():
    global verified
    p = remote('hax.perfect.blue', 31337)
    p.sendlineafter(b'Password: ', b'oAmzRFXPfsYgQHOdPtbr')
    p.sendlineafter(b'> ', b'5')
    verified = list(map(int, p.recvline().split(b' ')))


def upload(binary, answer, override_verify=False):
    binary = int(binary)
    if binary in verified: return True

    p.sendlineafter(b'Binary: ', binary)
    p.sendlineafter(b'Answer: ', answer)
    p.recvuntil(b'Verify: ')
    try:
        if b'False' in p.recvline():
            print(f'WARNING: binary {binary} has unverified answer')
            p.recvuntil(b'(y/n): ')
            if not override_verify:
                p.sendline(b'n')
                return False
            p.sendline(b'y')
            if b'WARNING' in p.recvuntil((b'> ', b'WARNING')):
                return False
            return True
        return True
    finally:
        p.close()

def main():
    if len(sys.argv) < 2:
        print('Usage: upload2.py FILE')
        quit()

    p = remote('hax.perfect.blue', 31337)
    p.sendlineafter(b'Password: ', b'oAmzRFXPfsYgQHOdPtbr')
    p.sendlineafter(b'> ', b'6')
    p.recvuntil(b'Input data line')
    p.recvline()

    with open(sys.argv[1], 'r') as f:
        for line in f:
            line = line.strip()
            p.sendline(bytes(line, 'utf8'))
        p.sendline(b'')
        p.interactive()


if __name__ == '__main__':
    main()


