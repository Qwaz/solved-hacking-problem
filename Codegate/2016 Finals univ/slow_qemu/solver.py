import base64

b64 = '2E42cdVbuQeh4g6aOnLhcN/GNpPXTck='

duser = b'defaultuser'
suser = b'routergod'

# decode cookie

cookie = base64.b64decode(b64)

num_arr = []

for i in range(len(cookie)):
    num_arr.append(cookie[i])

for i in range(len(num_arr)-1, -1, -1):
    for j in range(i):
        num_arr[i] -= num_arr[j]
    num_arr[i] %= 256
    if num_arr[i] < 0:
        num_arr[i] += 256

num_arr = list(reversed(num_arr))

seed = [0 for i in range(10)]

for i in range(len(duser)):
    seed[(len(num_arr)-len(duser)+i)%10] = num_arr[len(num_arr)-len(duser)+i] ^ duser[i]

for i in range(len(num_arr)):
    num_arr[i] ^= seed[i % 10]

print(bytes(num_arr).decode('ascii'))


# encode cookie

for i in range(len(suser)):
    num_arr[-len(duser)+i] = suser[i]

num_arr = num_arr[:len(suser)-len(duser)]

print(bytes(num_arr).decode('ascii'))

for i in range(len(num_arr)):
    num_arr[i] ^= seed[i % 10]

num_arr = list(reversed(num_arr))

for i in range(len(num_arr)):
    for j in range(i):
        num_arr[i] += num_arr[j]
    num_arr[i] %= 256

print(base64.b64encode(bytes(num_arr)))
