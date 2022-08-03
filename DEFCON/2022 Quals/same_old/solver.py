import binascii
print(hex(binascii.crc32(b"Hack the planet!"))) # 0x8d3e0ff4
print(hex(binascii.crc32(b"the"))) # 0x3c456de6

# perfect rt-c52gaaXxXxxXxxXXXXxXXXXxxxXxxxxXXxxXXXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
