# rbtree helped with the CRC reversing part
MAGIC = [
    0xBFA28E,
    0xA408CB,
    0x865C28,
    0x008F4D,
    0x786B04,
    0xA67791,
]

save = [[0 for _ in range(6)] for _ in range(256)]


def clicked(team_name, serial):
    work_arr = [MAGIC[i] for i in range(6)]

    target_key = b"Nautilus Institute"
    init()

    for c in target_key:
        digest(work_arr, c)

    for c in team_name:
        digest(work_arr, c)

    out_arr = decode(serial)
    print(out_arr)
    for i in range(len(out_arr) - 1, -1, -1):
        digest(work_arr, out_arr[i])

    gen_key = bytearray(18)
    for i in range(6):
        gen_key[i*3+0] = (work_arr[i] // (2**16)) & 0xFF
        gen_key[i*3+1] = (work_arr[i] // (2**8)) & 0xFF
        gen_key[i*3+2] = work_arr[i] & 0xFF

    if target_key == gen_key:
        print("Serial is valid")


def init():
    arr1 = [0, 0, 0, 0, 0, 0]
    arr2 = [0, 0, 0, 0, 0, 0]

    for i in range(6):
        for j in range(24):
            arr1[i] = (arr1[i] * 2) + (((MAGIC[5 - i] & (2**j)) != 0) & 1)

    for c in range(256):
        for i in range(5):
            arr2[i] = 0
        arr2[5] = c

        for i in range(8):
            x = arr2[5] & 1
            for j in range(5, 0, -1):
                arr2[j] = (arr2[j] // 2) + ((arr2[j - 1] & 1) * (2**23))
            arr2[0] = arr2[0] // 2

            if x:
                for j in range(6):
                    arr2[j] = arr2[j] ^^ arr1[j]

        for i in range(6):
            save[c][i] = arr2[i]


def decode(serial):
    ret = []

    while len(serial) % 4 != 0:
        serial += b"!"

    for i in range(len(serial) - 1, -1, -4):
        code = ord(serial[i]) - 33
        code = (code * 94) + (ord(serial[i - 1]) - 33)
        code = (code * 94) + (ord(serial[i - 2]) - 33)
        code = (code * 94) + (ord(serial[i - 3]) - 33)

        ret.append(code & 0xFF)
        code = code >> 8
        ret.append(code & 0xFF)
        code = code >> 8
        ret.append(code & 0xFF)

    return ret


def shuffle(work_arr):
    for i in range(6):
        work_arr[i] ^^= (2**24) - 1


def digest(work_arr, c):
    shuffle(work_arr)
    c = c ^^ (work_arr[5] & 0xFF)

    for i in range(5, 0, -1):
        work_arr[i] = (work_arr[i] >> 8) + (((work_arr[i - 1]) & 0xFF) << 16)

    work_arr[0] = work_arr[0] >> 8
    for i in range(6):
        work_arr[i] ^^= save[c][i]

    shuffle(work_arr)

init()

def get_res(out_arr):
    work_arr = [MAGIC[i] for i in range(6)]

    for c in b"Nautilus Institute":
        digest(work_arr, c)

    for c in b"perfect rt-c52gaa":
        digest(work_arr, c)

    for i in range(len(out_arr) - 1, -1, -1):
        digest(work_arr, out_arr[i])
    
    res = 0
    for v in work_arr:
        res <<= 24
        res |= v
    
    return res

def to_arr(res):
    return [ (res >> i) & 1 for i in range(144) ]

target = int.from_bytes(b"Nautilus Institute", 'big')
zero = get_res([0 for _ in range(18)])
target = vector(GF(2), to_arr(target))

mat = [[None for j in range(144)] for i in range(144)]
for i in range(18):
    for j in range(8):
        arr = [0 for _ in range(18)]
        arr[i] = 1 << j
        res = to_arr(get_res(arr))
        for k in range(144):
            mat[k][i * 8 + j] = res[k]

mat = Matrix(GF(2), mat)
res = mat.solve_right(target)
arr = [0 for _ in range(18)]
for i in range(144):
    if res[i]:
        arr[i // 8] |= 1 << (i % 8)

def encode(inp):
    ret = ''

    for i in range(0, len(inp), 3):
        v = inp[i] | (inp[i + 1] << 8) | (inp[i + 2] << 16)

        res = ''
        for j in range(4):
            res += chr((v % 94) + 33)
            v //= 94
        
        ret = res + ret
    
    return ret

print(arr)
print(decode(encode(arr)))

ans = encode(arr)
print(ans)

clicked(b"perfect rt-c52gaa", ans)
