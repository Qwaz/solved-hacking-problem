flag_str = "34 70 194 23 42 149 207 118 189 238 163 162 97 218 119 98 74 85 43 70 80 230 160 128 176 104 30 159 74 155 201 140 10 173 175 42 219 49 244 125 63 57 83 175 211 55 200 153 185 94 239 55 190 255 18 129 9 172 186 12"
encrypted_flag = list(map(int, flag_str.split()))

lcg_a = 6364136223846793005 & 0xffffffff
lcg_b = 1442695040888963407 & 0xffffffff
state = (-802458212630453242) & 0xffffffff

def lcg_proceed():
    global state
    state = ((state * lcg_a) + lcg_b) & 0xffffffff

idle_run = 1

flag = ""

for flag_char in encrypted_flag:
    # We only care about the last byte,
    # and running LCG 256 times preserves the last byte
    if idle_run < 256:
        for _ in range(idle_run):
            lcg_proceed()
    lcg_proceed()

    flag += chr((flag_char - state) & 0xff)
    idle_run *= 2

print(flag)
