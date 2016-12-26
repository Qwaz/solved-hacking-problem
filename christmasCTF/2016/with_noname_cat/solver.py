# -*- encoding: utf-8 -*-

from pwn import *
import datetime


def well512(init, round):
    state = [i + init for i in range(16)]

    index = 0
    for r in range(round % 0x2710):
        a = state[index]
        c = state[(index + 13) & 15]
        b = (a ^ c ^ (a << 16) ^ (c << 15)) & 0xffffffff
        c = state[(index + 9) & 15]
        c ^= c >> 11
        a = state[index] = b ^ c
        d = a ^ ((a << 5) & 0xDA442D20)
        index = (index + 15) & 15
        a = state[index]
        a ^= (b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28)) & 0xffffffff
        state[index] = a
    return state[index]


def expect_hp(epoch):
    return epoch % 300


def expect_atk(epoch, n_count):
    return well512(epoch % 1000, n_count) % 60


def expect_luk(epoch, n_count):
    return well512(epoch % 1000, n_count) % 10


def expect_def(epoch, m_count):
    return well512(epoch % 1000, m_count) % 76

flag = ''

for flag_index in range(22):
    while True:
        p = remote('devslave.com', 9001)

        n_count = 0
        m_count = 1

        # calculate current time
        p.recvuntil('m: 현재시간을 체크해본다.\n\n')
        p.sendline('m')

        year = int(p.recvuntil('년 ')[:-4])
        month = int(p.recvuntil('월 ')[:-4])
        day = int(p.recvuntil('일 ')[:-4])
        hour = int(p.recvuntil('시 ')[:-4])
        minute = int(p.recvuntil('분 ')[:-4])
        second = int(p.recvuntil('초')[:-3])

        epoch = int((
            datetime.datetime(year, month, day, hour, minute, second) -
            datetime.datetime(1970, 1, 1)
        ).total_seconds())

        log.success('%d %d/%d %d:%d:%d' % (year, month, day, hour, minute, second))

        while expect_atk(epoch, n_count) < 59:
            p.recvuntil('m: 현재시간을 체크해본다.\n\n')
            p.sendline('n')
            n_count += 1

        while expect_def(epoch, m_count) < 74:
            p.recvuntil('m: 현재시간을 체크해본다.\n\n')
            p.sendline('m')
            m_count += 1

        # start fighting
        p.recvuntil('m: 현재시간을 체크해본다.\n\n')
        p.sendline('y')

        p.recvuntil('숫자를 입력해주세요)\n')
        p.sendline(str(flag_index+1))

        # stat parsing
        p.recvuntil('HP:')
        cat_hp = int(p.recvline()[:-1])
        p.recvuntil('ATK:')
        cat_atk = int(p.recvline()[:-1])
        p.recvuntil('LUK:')
        cat_luk = int(p.recvline()[:-1])
        p.recvuntil('DEF:')
        cat_def = int(p.recvline()[:-1])

        log.success('cat - hp %d / atk %d / luk %d / def %d' % (cat_hp, cat_atk, cat_luk, cat_def))

        log.info('expect - hp %d / atk %d / luk %d / def %d' % (
            expect_hp(epoch),
            expect_atk(epoch, n_count),
            expect_luk(epoch, n_count),
            expect_def(epoch, m_count)
        ))

        s = p.recvall()
        if '플래그' in s:
            flag += s[s.index('{')+1:s.rindex('}')]
            log.success('Win! - flag[:%d] = %s' % (flag_index+1, flag))
            break
        else:
            log.failure('Lose...')

log.success(flag)
