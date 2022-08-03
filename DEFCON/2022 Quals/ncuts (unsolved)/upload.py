from pwn import *
context.log_level = 'warn'

p = remote('hax.perfect.blue', 31337)
p.sendlineafter(b'Password: ', b'oAmzRFXPfsYgQHOdPtbr')

def upload(binary, answer, override_verify=False):
    binary = bytes(str(int(binary)), 'utf8')
    answer = bytes(str(int(answer)), 'utf8')
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Binary: ', binary)
    p.sendlineafter(b'Answer: ', answer)
    p.recvuntil(b'Verify: ')
    if b'False' in p.recvline():
        print(f'WARNING: binary {binary} has unverified answer')
        p.recvuntil(b'(y/n): ')
        if not override_verify:
            p.sendline(b'n')
            return False
        p.sendline(b'y')
        if b'WARNING' in p.recvuntil((b'> ', b'WARNING')):
            p.unrecv('> ')
            return False
        return True
    return True

def prompt():
    print('1. Bulk upload')
    print('2. Simple upload')
    print('3. Toggle override_verify')

def main():
    override_verify = False
    while True:
        prompt()
        try:
            inp = input('> ')
            if inp == '': quit()
            res = int(inp)
        except ValueError:
            res = None
        if res == 1:
            file = input('File: ')
            if file == '': quit()
            file = file[:-1]
            try:
                f = open(file, 'r')
                for line in f:
                    binId, _, ans = line.partition(': ')
                    if not upload(binId, ans, override_verify):
                        print(f'Upload failed for {binId}')
                    else:
                        print(f'Uploaded {binId}')
            except:
                import traceback
                traceback.print_exc()
        elif res == 2:
            binId = input('Binary ID: ')
            ans = input('Answer: ')
            if not upload(binId, ans, override_verify):
                print('Upload failed')
        elif res == 3:
            override_verify = not override_verify
            print(f'override_verify = {override_verify}')
        else:
            print('Invalid choice!')

if __name__ == '__main__':
    main()


