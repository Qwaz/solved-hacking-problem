from binascii import unhexlify

# result of A * 36
magic1 = bytearray(unhexlify("739e80a23aae80a33ba4e79f78bac1f35ef9c1f33bb9ec9f558683f455fad5946cbfdd9f"))
magic2 = bytearray(unhexlify("4b8bf2814b8bf2814b8bf2814b8bf2814b8bf2814b8bf2814b8bf2814b8bf2814b8bf281"))

flag = ""

for i in range(36):
    x = (i + 3) % 4 + i // 4 * 4
    flag += chr(magic1[x] ^ magic2[x] ^ ord("A"))

# SECCON{byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun}
print(flag)
